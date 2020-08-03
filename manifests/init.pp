# Class: report_slack
#
# Send Puppet report information to slack
class report_slack (
  String[1] $slack_default_webhook,
  Boolean $enabled                                                 = true,
  Array[String] $slack_default_statuses                            = [ 'failed', 'changed' ],
  Array[String] $slack_attach_log_levels                           = ['warning', 'err', 'alert', 'emerg', 'crit'],
  Array[String] $slack_time_metrics_keys                           = ['config_retrieval', 'total'],
  String $owner                                                    = 'pe-puppet',
  String $group                                                    = 'pe-puppet',
  String $puppetmaster_service                                     = 'pe-puppetserver',
  String $gem_provider                                             = 'puppet_gem', #default for master 6.x
  String $slack_failed_color                                       = 'danger',
  String $slack_failed_emoji                                       = ':fire:',
  String $slack_changed_color                                      = 'warning',
  String $slack_changed_emoji                                      = ':warning:',
  String $slack_unchanged_color                                    = 'good',
  String $slack_noop_color                                         = '#439FE0',
  String $slack_noop_emoji                                         = ':shield:',
  String $slack_noop_event_color                                   = '#48B0F9',
  String $slack_changed_event_color                                = '#EA950B',
  String $slack_failed_event_color                                 = '#FF2D2D',
  String $slack_unchanged_emoji                                    = ':information_source:',
  Integer[0, 98] $slack_max_attach_count                           = 98, #2 are used by default, 100 is absolute max or API will reject message
  Boolean $slack_events_as_attach                                  = true,
  Boolean $slack_include_eval_time                                 = false,
  Boolean $slack_include_run_time_metrics                          = false,
  Boolean $slack_enable_proxy                                      = false,
  Optional[String] $slack_proxy_address                            = undef,
  Optional[String] $slack_proxy_port                               = undef,
  Optional[Array[String]] $slack_attach_log_tags                   = undef,
  Optional[Array[String]] $slack_include_patterns                  = undef,
  Optional[Array[String]] $slack_mute_patterns                     = undef,
  Optional[Hash[String, Hash[String, Array[String]]]] $slack_routing_data = undef
) {

  file { "${settings::confdir}/report_slack.yaml":
    ensure  => file,
    owner   => $owner,
    group   => $group,
    mode    => '0440',
    content => epp("${module_name}/report_slack.yaml.epp",
      { 'slack_default_webhook'          => $slack_default_webhook,
        'slack_failed_color'             => $slack_failed_color,
        'slack_failed_emoji'             => $slack_failed_emoji,
        'slack_changed_color'            => $slack_changed_color,
        'slack_changed_emoji'            => $slack_changed_emoji,
        'slack_unchanged_color'          => $slack_unchanged_color,
        'slack_unchanged_emoji'          => $slack_unchanged_emoji,
        'slack_noop_color'               => $slack_noop_color,
        'slack_noop_emoji'               => $slack_noop_emoji,
        'slack_noop_event_color'         => $slack_noop_event_color,
        'slack_changed_event_color'      => $slack_changed_event_color,
        'slack_failed_event_color'       => $slack_failed_event_color,
        'slack_events_as_attach'         => $slack_events_as_attach,
        'slack_include_eval_time'        => $slack_include_eval_time,
        'slack_include_run_time_metrics' => $slack_include_run_time_metrics,
        'slack_time_metrics_keys'        => $slack_time_metrics_keys,
        'slack_default_statuses'         => $slack_default_statuses,
        'slack_attach_log_levels'        => $slack_attach_log_levels,
        'slack_attach_log_tags'          => $slack_attach_log_tags,
        'slack_max_attach_count'         => $slack_max_attach_count,
        'slack_include_patterns'         => $slack_include_patterns,
        'slack_mute_patterns'            => $slack_mute_patterns,
        'slack_routing_data'             => $slack_routing_data,
        'slack_enable_proxy'             => $slack_enable_proxy,
        'slack_proxy_address'            => $slack_proxy_address,
        'slack_proxy_port'               => $slack_proxy_port,
      }),
  }

  package { 'slack-notifier':
    ensure   => '~> 2.3.2',
    provider => $gem_provider,
  }

  $report_ensure = $enabled ? {
    true  => present,
    false => absent,
  }

  ini_subsetting { 'slack reporting':
    ensure               => $report_ensure,
    path                 => $settings::config,
    section              => 'master',
    setting              => 'reports',
    subsetting_separator => ',',
    subsetting           => 'slack',
    value                => '',
  }

  Service <| title == $puppetmaster_service |> {
    subscribe +> Class[$title],
  }
}
