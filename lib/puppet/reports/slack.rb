# frozen_string_literal: true

# these two very much assumed to be here with puppet master install
require 'puppet'
require 'yaml'

begin
  require 'slack-notifier'
rescue LoadError => e
  raise unless e.message =~ /slack-notifier/

  friendly_ex = e.exception('please install slack-notifier gem first!')
  friendly_ex.set_backtrace(e.backtrace)
  raise friendly_ex
end

if Gem::Version.new(Puppet.version) < Gem::Version.new('4.0.0')
  Puppet.error 'Puppet 3.x is not supported in this version of the slack report processor'
end

Puppet::Reports.register_report(:slack) do
  configfile = File.join([File.dirname(Puppet.settings[:config]), 'report_slack.yaml'])
  raise(Puppet::ParseError, "[report_slack] config file #{configfile} not readable") unless File.exist?(configfile)

  config = YAML.load_file(configfile)

  SLACK_DEFAULT_WEBHOOK = config[:slack_report_default_webhook]
  SLACK_DEFAULT_STATUSES = Array(config[:slack_report_default_statuses] || %w[failed changed])
  SLACK_ATTACH_LOG_LEVELS = Array(config[:slack_attach_log_levels] || %w[:warning :err :alert :emerg :crit])
  SLACK_ATTACH_LOG_TAGS = Array(config[:slack_attach_log_tags] || [])
  PUPPET_TIME_METRICS_KEYNAMES = Array(config[:slack_report_time_metric_keys] || %w[config_retrieval total])
  SLACK_INCLUDE_REGEX_PATTERNS = Array(config[:slack_report_include_patterns] || []) # if there's nothing, we'll include all
  SLACK_MUTE_REGEX_PATTERNS = Array(config[:slack_report_mute_patterns] || []) # mute checked first and overrides include
  SLACK_ROUTING_DATA = Hash(config[:slack_report_routing_data] || {})
  # set the default colors if not defined in the config
  # !!!!emoji is MANDATORY!!!!!
  SLACK_FAILED_COLOR = config[:slack_report_failed_color] || 'danger'
  SLACK_FAILED_EMOJI = config[:slack_report_failed_emoji] || ':fire:'
  SLACK_CHANGED_COLOR = config[:slack_report_changed_color] || 'warning'
  SLACK_CHANGED_EMOJI = config[:slack_report_changed_emoji] || ':warning:'
  SLACK_UNCHANGED_COLOR = config[:slack_report_unchanged_color] || 'good'
  SLACK_UNCHANGED_EMOJI = config[:slack_report_unchanged_emoji] || ':information_source:'
  SLACK_NOOP_COLOR = config[:slack_report_noop_color] || '#439FE0'
  SLACK_NOOP_EMOJI = config[:slack_report_noop_emoji] || ':shield:'
  SLACK_NOOP_EVENT_COLOR = config[:slack_report_noop_event_color] || '#48B0F9'
  SLACK_CHANGED_EVENT_COLOR = config[:slack_report_changed_event_color] || '#EA950B'
  SLACK_FAILED_EVENT_COLOR = config[:slack_report_failed_event_color] || '#FF2D2D'
  SLACK_EVENTS_AS_ATTACH = config[:slack_report_events_as_attach] || true
  SLACK_INCLUDE_EVAL_TIME = config[:slack_report_include_eval_time] || false
  SLACK_INCLUDE_RUN_TIME_METRICS = config[:slack_report_include_run_time_metrics] || false
  SLACK_MAX_ATTACH_COUNT = config[:slack_report_max_attach_count] || 98
  SLACK_PROXY_ADDRESS = config[:slack_proxy_address] || false
  SLACK_PROXY_PORT = config[:slack_proxy_port] || false

  def color(status, noop, isevent)
    if noop
      isevent ? SLACK_NOOP_EVENT_COLOR : SLACK_NOOP_COLOR
    else
      case status
      when 'failed'
        isevent ? SLACK_FAILED_EVENT_COLOR : SLACK_FAILED_COLOR
      when 'changed'
        isevent ? SLACK_CHANGED_EVENT_COLOR : SLACK_CHANGED_COLOR
      when 'unchanged'
        SLACK_UNCHANGED_COLOR
      else
        'good'
      end
    end
  end

  def emoji(status, noop)
    if noop
      SLACK_NOOP_EMOJI
    else
      case status
      when 'failed'
        SLACK_FAILED_EMOJI
      when 'changed'
        SLACK_CHANGED_EMOJI
      when 'unchanged'
        SLACK_UNCHANGED_EMOJI
      else
        SLACK_FAILED_EMOJI
      end
    end
  end

  def extract_logentries(report_logs, log_levels, tags)
    retval = []
    report_logs.each do |log|
      if log_levels.include?(log.level.to_s) || log_levels.include?('all')
        retval << "\n```#{log.level}:[#{log.source}]: #{log.message}```\n"
        next
      end
      tags.each do |tag|
        retval << "\n```TAG: #{tag} -- #{log.level}:[#{log.source}]: #{log.message}```\n" if log.tags.include?(tag)
      end
    end
    retval
  end

  def get_status_header(status, host, noop)
    retval = if !status.nil?
               if status == 'failed'
                 "#{emoji(status, noop)} Puppet failed on #{host}"
               elsif status == 'changed'
                 "#{emoji(status, noop)} Puppet changed resources on #{host}"
               elsif status == 'unchanged'
                 "#{emoji(status, noop)} Puppet ran on, and left #{host} unchanged"
               else
                 "#{emoji(status, noop)} Puppet ran on #{host}"
               end
             else
               "#{emoji(status, noop)} status indeterminate for puppet run on #{host}"
    end
    retval
  end

  def append_fields_runtime_metrics(fields_original, report_metrics, time_metrics)
    retval = fields_original
    report_metrics.each do |metric, data|
      next unless metric == 'time' # do not process events at all

      data.values.each do |item|
        if time_metrics.include?(item[0])
          retval << { "title": "#{item[1]} time", "value": "#{item[2]}s", "short": false }
        end
      end
    end
    retval
  end

  def get_items_attachment_array(collection_state, include_eval_time, collection, noop)
    retval = []
    collection.each do |s|
      item_fields = []
      item_fields << { "title": 'Resource Type', "value": s.resource_type.to_s, "short": true }
      item_fields << { "title": 'Change Count', "value": s.change_count.to_s, "short": true }
      item_fields << { "title": 'File', "value": s.file.to_s, "short": false }
      item_fields << { "title": 'Code Line', "value": s.line.to_s, "short": true }
      item_fields << { "title": 'Out of Sync', "value": s.out_of_sync.to_s, "short": true } if s.out_of_sync
      item_fields << { "title": 'Changed', "value": s.changed.to_s, "short": true } if s.changed
      item_fields << { "title": 'Failed', "value": s.failed.to_s, "short": true } if s.failed
      item_fields << { "title": 'Skipped', "value": s.skipped.to_s, "short": true } if s.skipped
      item_events = s.events
      item_events.each do |eventitem|
        item_fields << { "title": "EVENT - #{eventitem.name}", "value": eventitem.message.to_s, "short": false }
      end
      item_fields << { "title": 'Eval Time', "value": "#{s.evaluation_time}s", "short": true } if include_eval_time

      item_attach = {
        fallback: "#{collection_state} RESOURCE - *#{s.title}* in _#{s.file}:*#{s.line}*_",
        text: "#{emoji(collection_state.to_s, noop)}*#{collection_state} RESOURCE* - _#{s.title}_",
        fields: item_fields,
        color: color(status, self.noop, true).to_s,
        mrkdwn: true
      }
      retval << item_attach
    end
    retval
  end

  def get_regex_arr_from_string_arr(str_array)
    retval = []
    str_array.each do |s|
      retval << /#{s}/
    end
    retval
  end

  # noinspection RubyParameterNamingConvention
  def is_host_blocked(hostname, pattern_str_arr, block_match_bool_state, debug_reason_for_block)
    begin
      test_patterns_regex = Regexp.union(get_regex_arr_from_string_arr(pattern_str_arr))
    rescue StandardError => e
      raise(Puppet::ParseError, "[report_slack] unable to parse slack regex pattern array: #{e}")
    end
    ismatch = hostname.match(test_patterns_regex)

    if ismatch
      if block_match_bool_state # blocked if is a match
        Puppet.debug "[report_slack] REGEX MATCH - blocked for #{hostname} due to #{debug_reason_for_block}."
        true
      else
        false # not blocked
      end
    else
      if block_match_bool_state # is not a match in this code block
        false # not blocked
      else
        Puppet.debug "[report_slack] REGEX NOT MATCH - blocked for #{hostname} due to #{debug_reason_for_block}."
        true # blocked if not a match
      end
    end
  end

  def append_items_to_event_data(collection_state, event_data, collection)
    retval = event_data
    retval << "\n*The resources that _#{collection_state}_ are:*\n@@@\n"
    collection.each do |s|
      retval << "*#{s.title}* in _#{s.file}:*#{s.line}*_ - "
      item_events = s.events
      item_events.each do |eventitem|
        retval << "\n*EVENT:* `#{eventitem.name}` \n*DETAILS:* `#{eventitem.message}`\n"
      end
    end
    retval << "\n@@@\n"
    retval
  end

  def get_default_fields(environment, agent_version, total_resource_count,
                         changed_resources, failed_resources, catalog_status,
                         corrective_change, noop, noop_pending, job_id)
    retval = []
    retval << { "title": 'Environment', "value": environment.to_s, "short": true }
    retval << { "title": 'Total Resource', "value": total_resource_count.to_s, "short": true }
    retval << { "title": 'Changed Resource', "value": changed_resources.to_s, "short": true } if changed_resources > 0
    retval << { "title": 'Failed Resource', "value": failed_resources.to_s, "short": true } if failed_resources > 0
    retval << { "title": 'Agent Version', "value": agent_version.to_s, "short": true }
    if catalog_status != 'not_used'
      retval << { "title": 'Cached Catalog Status', "value": catalog_status.to_s, "short": true }
    end
    retval << { "title": 'Corrective Change', "value": corrective_change.to_s, "short": true } if corrective_change
    retval << { "title": 'noop', "value": noop.to_s, "short": true } if noop
    retval << { "title": 'noop pending', "value": noop_pending.to_s, "short": true } if noop_pending
    retval << { "title": 'Job ID', "value": job_id.to_s, "short": true } unless job_id.nil?
    retval
  end

  def post_to_slack(webhook, event_title, attachments_array)
    Puppet.debug '[report_slack] beginning webhook post'
    if SLACK_PROXY_ADDRESS && SLACK_PROXY_PORT
      Puppet.debug "[report_slack] webhook post via proxy: #{SLACK_PROXY_ADDRESS} : #{SLACK_PROXY_PORT}"
      notifier = Slack::Notifier.new webhook, http_options: {
        open_timeout: 5,
        proxy_address: SLACK_PROXY_ADDRESS,
        proxy_port: SLACK_PROXY_PORT,
        proxy_from_env: false
      }
      notifier.post text: event_title, attachments: attachments_array
    else
      Puppet.debug '[report_slack] webhook post default no proxy'
      notifier = Slack::Notifier.new webhook, http_options: { open_timeout: 5 }
      notifier.post text: event_title, attachments: attachments_array
    end
  end

  def get_states_across_routing(hostname, current_status, slack_routing_data, slack_default_states, slack_default_webhook)
    retval_states_across_routing = []
    retval_relevant_hooks = []
    relevant_routing_data = false
    Puppet.debug '[report_slack] beginning evaluation of routing data...'

    slack_routing_data.each do |pattern, routing_details_hash|
      next unless hostname.match(/#{pattern}/)

      Puppet.debug "[report_slack] regex match on pattern from routing data: #{pattern}"
      if routing_details_hash.key?('report_states')
        routing_details_hash.each do |attribute, data|
          next unless attribute == 'report_states'

          data.each do |s|
            retval_states_across_routing << s
            next unless current_status == s

            Puppet.debug "[report_slack] regex match on pattern #{pattern} - HAS STATUS DATA MATCHING current_status: #{s}"
            if routing_details_hash.key?('webhooks')
              routing_details_hash.each do |attribute_inner, data_inner|
                next unless attribute_inner == 'webhooks'

                data_inner.each do |hook|
                  Puppet.debug "[report_slack] regex match on pattern #{pattern} - ADDED MATCHED HOOK #{hook}"
                  retval_relevant_hooks << hook
                  relevant_routing_data = true
                end
              end
            else
              Puppet.debug "[report_slack] regex match on pattern #{pattern} - NO HOOK DATA, ADDING DEFAULT HOOK"
              retval_relevant_hooks << slack_default_webhook
              relevant_routing_data = true
            end
          end
        end
      else
        Puppet.debug "[report_slack] regex match on pattern #{pattern} - NO STATE DATA, ADDING DEFAULT STATES"
        slack_default_states.each do |s|
          retval_states_across_routing << s
          Puppet.debug "[report_slack] regex match on pattern #{pattern} - ADDED DEFAULT STATUS #{s}"
          if current_status == s
            if routing_details_hash.key?('webhooks')
              routing_details_hash.each do |attribute, data|
                next unless attribute == 'webhooks'

                data.each do |hook|
                  Puppet.debug "[report_slack] regex match on pattern #{pattern} - ADDED MATCHED HOOK #{hook}"
                  retval_relevant_hooks << hook
                  relevant_routing_data = true
                end
              end
            else
              retval_relevant_hooks << slack_default_webhook
              relevant_routing_data = true
            end
          end
        end
      end
    end
    unless relevant_routing_data
      if slack_default_states.include?(current_status)
        Puppet.debug "[report_slack] NO RELEVANT ROUTING DATA: ADDING DEFAULT STATES - ADDING DEFAULT HOOK: #{slack_default_webhook}"
        retval_states_across_routing = slack_default_states
        retval_relevant_hooks << slack_default_webhook
      end
    end
    retval_states_across_routing.uniq!
    retval_relevant_hooks.uniq!
    [retval_states_across_routing, retval_relevant_hooks]
  end

  def process
    if ENV['BLOCK_PUPPET_REPORT_SLACK'] == 'true'
      Puppet.debug "[report_slack] blocked from operating due to presence of ENV VAR 'BLOCK_PUPPET_REPORT_SLACK' = true"
      return
    end

    unless SLACK_MUTE_REGEX_PATTERNS.empty?
      return if is_host_blocked(host, SLACK_MUTE_REGEX_PATTERNS, true, 'matching mute patterns')
    end

    unless SLACK_INCLUDE_REGEX_PATTERNS.empty?
      return if is_host_blocked(host, SLACK_INCLUDE_REGEX_PATTERNS, false, 'NOT matching include patterns')
    end

    if !SLACK_ROUTING_DATA.empty?
      routing_targets = get_states_across_routing(host, status, SLACK_ROUTING_DATA, SLACK_DEFAULT_STATUSES, SLACK_DEFAULT_WEBHOOK)
      states_across_routing = routing_targets[0]
      hooks_for_report = routing_targets[1]
    else
      states_across_routing = SLACK_DEFAULT_STATUSES
      hooks_for_report = []
      hooks_for_report << SLACK_DEFAULT_WEBHOOK
    end

    return unless states_across_routing.include?(status) || states_across_routing.include?('all')

    logentries = extract_logentries(logs, SLACK_ATTACH_LOG_LEVELS, SLACK_ATTACH_LOG_TAGS)
    logstring = ''
    logstring = logentries.join unless logentries.empty?
    event_title = get_status_header(status, host, noop)
    event_data = ''
    attachments_array = []
    changed_attachment_array = []
    failed_attachment_array = []
    total_resource_count = resource_statuses.length
    changed_resources = resource_statuses.values.find_all(&:changed)
    failed_resources = resource_statuses.values.find_all(&:failed)
    config_version_blurb = defined?(configuration_version) ? "applied version #{configuration_version} and" : ''
    event_data << "Puppet #{config_version_blurb} changed #{changed_resources.length} resource(s) out of #{total_resource_count}."
    fields = get_default_fields(environment, puppet_version, total_resource_count,
                                changed_resources.length, failed_resources.length, cached_catalog_status,
                                corrective_change, noop, noop_pending, job_id)

    if SLACK_INCLUDE_RUN_TIME_METRICS
      fields = append_fields_runtime_metrics(fields, metrics, PUPPET_TIME_METRICS_KEYNAMES)
    end

    unless changed_resources.empty?
      if SLACK_EVENTS_AS_ATTACH && (changed_resources.length + failed_resources.length) <= SLACK_MAX_ATTACH_COUNT
        changed_attachment_array = get_items_attachment_array('changed', SLACK_INCLUDE_EVAL_TIME, changed_resources, noop)
      else
        event_data = append_items_to_event_data('changed', event_data, changed_resources)
      end
    end

    unless failed_resources.empty?
      if SLACK_EVENTS_AS_ATTACH && (changed_resources.length + failed_resources.length) <= SLACK_MAX_ATTACH_COUNT
        failed_attachment_array = get_items_attachment_array('failed', SLACK_INCLUDE_EVAL_TIME, failed_resources, noop)
      else
        event_data = append_items_to_event_data('failed', event_data, failed_resources)
      end
    end

    msg_attach = {
      fallback: "Puppet run for #{host} : #{status} at #{Time.now.asctime} on #{configuration_version} in #{environment}",
      text: event_data.to_s,
      fields: fields,
      color: color(status, noop, false).to_s,
      mrkdwn: true
    }

    log_attach = {
      fallback: "Relevant Log Entries raw fallback: #{logstring}",
      text: "*ATTACHED LOGS:*\n#{logstring}",
      color: color(status, noop, false).to_s,
      mrkdwn: true
    }

    attachments_array << msg_attach
    changed_attachment_array.each do |changed_attachment|
      attachments_array << changed_attachment
    end
    failed_attachment_array.each do |failed_attachment|
      attachments_array << failed_attachment
    end

    attachments_array << log_attach unless logstring.empty?

    Puppet.debug "[report_slack] slack hook POST(s) for #{host} - \n  - status: #{status}\n  - hooks: #{hooks_for_report}"
    hooks_for_report.each do |hook|
      post_to_slack(hook, event_title, attachments_array)
    end
  end
end
