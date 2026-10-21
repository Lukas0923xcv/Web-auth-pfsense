<?php
/*
 * Declarations of the pfSense CE 2.8 functions and classes this package
 * calls, for PHPStan only (never loaded on the firewall). Signatures follow
 * pfSense's src/etc/inc and src/usr/local/www/classes; bodies are empty.
 */

/* config.lib.inc */
/** @return mixed */
function config_get_path(string $path, mixed $default = null) {}
function config_set_path(string $path, mixed $value, mixed $default = null): mixed {}
function config_del_path(string $path): mixed {}
/** @return array<mixed>|false */
function write_config(string $desc = 'Unknown', bool $backup = true, bool $write_config_only = false) {}
function config_read_file(bool $use_backup = false, bool $use_cache = true): bool {}

/* xmlparse.inc */
/**
 * @param array<string> $rootobj
 * @return array<mixed>|false|-1
 */
function parse_xml_config(string $cffile, array $rootobj, bool $isstring = false) {}

/* globals.inc */
/** @return mixed */
function g_get(string $name, mixed $default = null) {}

/* auth.inc, authgui.inc */
function phpsession_begin(): void {}
function phpsession_end(bool $write = false): void {}
function phpsession_destroy(): void {}
function isAjax(): bool {}
/** @return array<string, mixed> */
function get_user_settings(string $username): array {}

/* notices.inc */
function file_notice(string $id, string $notice, string $category = 'General', string $url = '', int $priority = 1, bool $local_only = false): mixed {}

/* util.inc, services.inc */
function is_platform_booting(bool $on_console = false): bool {}
function install_cron_job(string $command, bool $active = false, string $minute = '0', string $hour = '*', string $monthday = '*',
    string $month = '*', string $weekday = '*', string $who = 'root', bool $write_config = true): void {}

/* pfsense-utils.inc (loaded with authgui.inc; may be missing elsewhere, so callers check function_exists()) */
/** @return array<string, string> */
function get_configured_ip_addresses(): array {}
/** @return array<string, string> */
function get_configured_ipv6_addresses(bool $linklocal_fallback = false): array {}

/* guiconfig.inc */
/** @param array<array{0: string, 1: bool, 2: string}> $tab_array */
function display_top_tabs(array $tab_array, bool $no_drop_down = false, string $type = 'pills', string $usepost = ''): void {}
/** @param array<string> $input_errors */
function print_input_errors(array $input_errors): void {}
function print_info_box(string $msg, string $class = 'alert-warning', mixed $btnname = 'close', string $btntext = '', string $btnicon = '', string $btnclass = 'default'): void {}

/* classes/Form*.class.php */
class Form_Element
{
	public function setHelp(string $text): static {}
	public function __toString(): string {}
}
class Form_Input extends Form_Element
{
	/** @param array<string, mixed> $attributes */
	public function __construct(string $name, ?string $title, string $type = 'text', mixed $value = null, array $attributes = []) {}
}
class Form_Checkbox extends Form_Input
{
	public function __construct(string $name, ?string $title, string $description, bool $checked, string $value = 'yes') {}
}
class Form_Textarea extends Form_Input
{
	public function __construct(string $name, ?string $title, mixed $value) {}
}
class Form_Select extends Form_Input
{
	/** @param array<string, string> $values */
	public function __construct(string $name, ?string $title, mixed $value, array $values, bool $allowMultiple = false) {}
}
class Form_Section extends Form_Element
{
	public function __construct(string $title, ?string $id = null, bool $collapsible = false) {}
	public function addInput(Form_Input $input): Form_Input {}
}
class Form extends Form_Element
{
	public function __construct(mixed $submit = null) {}
	public function add(Form_Section $section): Form_Section {}
	public function addGlobal(Form_Input $input): Form_Input {}
}
