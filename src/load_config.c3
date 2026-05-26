module vipe::load_config;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawLoadConfig32 @packed
{
    uint size;
    uint time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint global_flags_clear;
    uint global_flags_set;
    uint critical_section_default_timeout;
    uint de_commit_free_block_threshold;
    uint de_commit_total_free_threshold;
    uint lock_prefix_table;
    uint maximum_allocation_size;
    uint virtual_memory_threshold;
    uint process_affinity_mask;
    uint process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    uint edit_list;
    uint security_cookie;
    uint se_handler_table;
    uint se_handler_count;
    uint guard_cf_check_function_pointer;
    uint guard_cf_dispatch_function_pointer;
    uint guard_cf_function_table;
    uint guard_cf_function_count;
    uint guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint ci_catalog_offset;
    uint ci_reserved;
    uint guard_address_taken_iat_entry_table;
    uint guard_address_taken_iat_entry_count;
    uint guard_long_jump_target_table;
    uint guard_long_jump_target_count;
    uint dynamic_value_reloc_table;
    uint chpe_metadata_pointer;
    uint guard_rf_failure_routine;
    uint guard_rf_failure_routine_function_pointer;
    uint dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    uint guard_rf_verify_stack_pointer_function_pointer;
    uint hot_patch_table_offset;
    uint reserved3;
    uint enclave_configuration_pointer;
    uint volatile_metadata_pointer;
    uint guard_eh_continuation_table;
    uint guard_eh_continuation_count;
    uint guard_xfg_check_function_pointer;
    uint guard_xfg_dispatch_function_pointer;
    uint guard_xfg_table_dispatch_function_pointer;
    uint cast_guard_os_determined_failure_mode;
    uint guard_memcpy_function_pointer;
}

struct VipeRawLoadConfig64 @packed
{
    uint size;
    uint time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint global_flags_clear;
    uint global_flags_set;
    uint critical_section_default_timeout;
    ulong de_commit_free_block_threshold;
    ulong de_commit_total_free_threshold;
    ulong lock_prefix_table;
    ulong maximum_allocation_size;
    ulong virtual_memory_threshold;
    ulong process_affinity_mask;
    uint process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    ulong edit_list;
    ulong security_cookie;
    ulong se_handler_table;
    ulong se_handler_count;
    ulong guard_cf_check_function_pointer;
    ulong guard_cf_dispatch_function_pointer;
    ulong guard_cf_function_table;
    ulong guard_cf_function_count;
    uint guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint ci_catalog_offset;
    uint ci_reserved;
    ulong guard_address_taken_iat_entry_table;
    ulong guard_address_taken_iat_entry_count;
    ulong guard_long_jump_target_table;
    ulong guard_long_jump_target_count;
    ulong dynamic_value_reloc_table;
    ulong chpe_metadata_pointer;
    ulong guard_rf_failure_routine;
    ulong guard_rf_failure_routine_function_pointer;
    uint dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    ulong guard_rf_verify_stack_pointer_function_pointer;
    uint hot_patch_table_offset;
    uint reserved3;
    ulong enclave_configuration_pointer;
    ulong volatile_metadata_pointer;
    ulong guard_eh_continuation_table;
    ulong guard_eh_continuation_count;
    ulong guard_xfg_check_function_pointer;
    ulong guard_xfg_dispatch_function_pointer;
    ulong guard_xfg_table_dispatch_function_pointer;
    ulong cast_guard_os_determined_failure_mode;
    ulong guard_memcpy_function_pointer;
}

//
// View structures definition
//

struct VipeViewLoadConfig
{
    bool is64;
    union
    {
        VipeRawLoadConfig32* h32;
        VipeRawLoadConfig64* h64;
    }
}

// uint fields (same width in both 32 and 64)

fn uint VipeViewLoadConfig.get_size(&self)
    => self.is64 ? self.h64.size : self.h32.size;
fn void VipeViewLoadConfig.set_size(&self, uint v)
{
    if (self.is64) { self.h64.size = v; } else { self.h32.size = v; }
}

fn uint VipeViewLoadConfig.get_time_date_stamp(&self)
    => self.is64 ? self.h64.time_date_stamp : self.h32.time_date_stamp;
fn void VipeViewLoadConfig.set_time_date_stamp(&self, uint v)
{
    if (self.is64) { self.h64.time_date_stamp = v; } else { self.h32.time_date_stamp = v; }
}

fn ushort VipeViewLoadConfig.get_major_version(&self)
    => self.is64 ? self.h64.major_version : self.h32.major_version;
fn void VipeViewLoadConfig.set_major_version(&self, ushort v)
{
    if (self.is64) { self.h64.major_version = v; } else { self.h32.major_version = v; }
}

fn ushort VipeViewLoadConfig.get_minor_version(&self)
    => self.is64 ? self.h64.minor_version : self.h32.minor_version;
fn void VipeViewLoadConfig.set_minor_version(&self, ushort v)
{
    if (self.is64) { self.h64.minor_version = v; } else { self.h32.minor_version = v; }
}

fn uint VipeViewLoadConfig.get_global_flags_clear(&self)
    => self.is64 ? self.h64.global_flags_clear : self.h32.global_flags_clear;
fn void VipeViewLoadConfig.set_global_flags_clear(&self, uint v)
{
    if (self.is64) { self.h64.global_flags_clear = v; } else { self.h32.global_flags_clear = v; }
}

fn uint VipeViewLoadConfig.get_global_flags_set(&self)
    => self.is64 ? self.h64.global_flags_set : self.h32.global_flags_set;
fn void VipeViewLoadConfig.set_global_flags_set(&self, uint v)
{
    if (self.is64) { self.h64.global_flags_set = v; } else { self.h32.global_flags_set = v; }
}

fn uint VipeViewLoadConfig.get_critical_section_default_timeout(&self)
    => self.is64 ? self.h64.critical_section_default_timeout : self.h32.critical_section_default_timeout;
fn void VipeViewLoadConfig.set_critical_section_default_timeout(&self, uint v)
{
    if (self.is64) { self.h64.critical_section_default_timeout = v; } else { self.h32.critical_section_default_timeout = v; }
}

fn uint VipeViewLoadConfig.get_process_heap_flags(&self)
    => self.is64 ? self.h64.process_heap_flags : self.h32.process_heap_flags;
fn void VipeViewLoadConfig.set_process_heap_flags(&self, uint v)
{
    if (self.is64) { self.h64.process_heap_flags = v; } else { self.h32.process_heap_flags = v; }
}

fn ushort VipeViewLoadConfig.get_csd_version(&self)
    => self.is64 ? self.h64.csd_version : self.h32.csd_version;
fn void VipeViewLoadConfig.set_csd_version(&self, ushort v)
{
    if (self.is64) { self.h64.csd_version = v; } else { self.h32.csd_version = v; }
}

fn ushort VipeViewLoadConfig.get_dependent_load_flags(&self)
    => self.is64 ? self.h64.dependent_load_flags : self.h32.dependent_load_flags;
fn void VipeViewLoadConfig.set_dependent_load_flags(&self, ushort v)
{
    if (self.is64) { self.h64.dependent_load_flags = v; } else { self.h32.dependent_load_flags = v; }
}

fn uint VipeViewLoadConfig.get_guard_flags(&self)
    => self.is64 ? self.h64.guard_flags : self.h32.guard_flags;
fn void VipeViewLoadConfig.set_guard_flags(&self, uint v)
{
    if (self.is64) { self.h64.guard_flags = v; } else { self.h32.guard_flags = v; }
}

// ulong fields (uint in 32, ulong in 64)

fn ulong VipeViewLoadConfig.get_de_commit_free_block_threshold(&self)
    => self.is64 ? self.h64.de_commit_free_block_threshold : (ulong)self.h32.de_commit_free_block_threshold;
fn void VipeViewLoadConfig.set_de_commit_free_block_threshold(&self, ulong v)
{
    if (self.is64) { self.h64.de_commit_free_block_threshold = v; } else { self.h32.de_commit_free_block_threshold = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_de_commit_total_free_threshold(&self)
    => self.is64 ? self.h64.de_commit_total_free_threshold : (ulong)self.h32.de_commit_total_free_threshold;
fn void VipeViewLoadConfig.set_de_commit_total_free_threshold(&self, ulong v)
{
    if (self.is64) { self.h64.de_commit_total_free_threshold = v; } else { self.h32.de_commit_total_free_threshold = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_lock_prefix_table(&self)
    => self.is64 ? self.h64.lock_prefix_table : (ulong)self.h32.lock_prefix_table;
fn void VipeViewLoadConfig.set_lock_prefix_table(&self, ulong v)
{
    if (self.is64) { self.h64.lock_prefix_table = v; } else { self.h32.lock_prefix_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_maximum_allocation_size(&self)
    => self.is64 ? self.h64.maximum_allocation_size : (ulong)self.h32.maximum_allocation_size;
fn void VipeViewLoadConfig.set_maximum_allocation_size(&self, ulong v)
{
    if (self.is64) { self.h64.maximum_allocation_size = v; } else { self.h32.maximum_allocation_size = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_virtual_memory_threshold(&self)
    => self.is64 ? self.h64.virtual_memory_threshold : (ulong)self.h32.virtual_memory_threshold;
fn void VipeViewLoadConfig.set_virtual_memory_threshold(&self, ulong v)
{
    if (self.is64) { self.h64.virtual_memory_threshold = v; } else { self.h32.virtual_memory_threshold = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_process_affinity_mask(&self)
    => self.is64 ? self.h64.process_affinity_mask : (ulong)self.h32.process_affinity_mask;
fn void VipeViewLoadConfig.set_process_affinity_mask(&self, ulong v)
{
    if (self.is64) { self.h64.process_affinity_mask = v; } else { self.h32.process_affinity_mask = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_edit_list(&self)
    => self.is64 ? self.h64.edit_list : (ulong)self.h32.edit_list;
fn void VipeViewLoadConfig.set_edit_list(&self, ulong v)
{
    if (self.is64) { self.h64.edit_list = v; } else { self.h32.edit_list = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_security_cookie(&self)
    => self.is64 ? self.h64.security_cookie : (ulong)self.h32.security_cookie;
fn void VipeViewLoadConfig.set_security_cookie(&self, ulong v)
{
    if (self.is64) { self.h64.security_cookie = v; } else { self.h32.security_cookie = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_se_handler_table(&self)
    => self.is64 ? self.h64.se_handler_table : (ulong)self.h32.se_handler_table;
fn void VipeViewLoadConfig.set_se_handler_table(&self, ulong v)
{
    if (self.is64) { self.h64.se_handler_table = v; } else { self.h32.se_handler_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_se_handler_count(&self)
    => self.is64 ? self.h64.se_handler_count : (ulong)self.h32.se_handler_count;
fn void VipeViewLoadConfig.set_se_handler_count(&self, ulong v)
{
    if (self.is64) { self.h64.se_handler_count = v; } else { self.h32.se_handler_count = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_cf_check_function_pointer(&self)
    => self.is64 ? self.h64.guard_cf_check_function_pointer : (ulong)self.h32.guard_cf_check_function_pointer;
fn void VipeViewLoadConfig.set_guard_cf_check_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_cf_check_function_pointer = v; } else { self.h32.guard_cf_check_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_cf_dispatch_function_pointer(&self)
    => self.is64 ? self.h64.guard_cf_dispatch_function_pointer : (ulong)self.h32.guard_cf_dispatch_function_pointer;
fn void VipeViewLoadConfig.set_guard_cf_dispatch_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_cf_dispatch_function_pointer = v; } else { self.h32.guard_cf_dispatch_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_cf_function_table(&self)
    => self.is64 ? self.h64.guard_cf_function_table : (ulong)self.h32.guard_cf_function_table;
fn void VipeViewLoadConfig.set_guard_cf_function_table(&self, ulong v)
{
    if (self.is64) { self.h64.guard_cf_function_table = v; } else { self.h32.guard_cf_function_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_cf_function_count(&self)
    => self.is64 ? self.h64.guard_cf_function_count : (ulong)self.h32.guard_cf_function_count;
fn void VipeViewLoadConfig.set_guard_cf_function_count(&self, ulong v)
{
    if (self.is64) { self.h64.guard_cf_function_count = v; } else { self.h32.guard_cf_function_count = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_address_taken_iat_entry_table(&self)
    => self.is64 ? self.h64.guard_address_taken_iat_entry_table : (ulong)self.h32.guard_address_taken_iat_entry_table;
fn void VipeViewLoadConfig.set_guard_address_taken_iat_entry_table(&self, ulong v)
{
    if (self.is64) { self.h64.guard_address_taken_iat_entry_table = v; } else { self.h32.guard_address_taken_iat_entry_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_address_taken_iat_entry_count(&self)
    => self.is64 ? self.h64.guard_address_taken_iat_entry_count : (ulong)self.h32.guard_address_taken_iat_entry_count;
fn void VipeViewLoadConfig.set_guard_address_taken_iat_entry_count(&self, ulong v)
{
    if (self.is64) { self.h64.guard_address_taken_iat_entry_count = v; } else { self.h32.guard_address_taken_iat_entry_count = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_long_jump_target_table(&self)
    => self.is64 ? self.h64.guard_long_jump_target_table : (ulong)self.h32.guard_long_jump_target_table;
fn void VipeViewLoadConfig.set_guard_long_jump_target_table(&self, ulong v)
{
    if (self.is64) { self.h64.guard_long_jump_target_table = v; } else { self.h32.guard_long_jump_target_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_long_jump_target_count(&self)
    => self.is64 ? self.h64.guard_long_jump_target_count : (ulong)self.h32.guard_long_jump_target_count;
fn void VipeViewLoadConfig.set_guard_long_jump_target_count(&self, ulong v)
{
    if (self.is64) { self.h64.guard_long_jump_target_count = v; } else { self.h32.guard_long_jump_target_count = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_rf_failure_routine(&self)
    => self.is64 ? self.h64.guard_rf_failure_routine : (ulong)self.h32.guard_rf_failure_routine;
fn void VipeViewLoadConfig.set_guard_rf_failure_routine(&self, ulong v)
{
    if (self.is64) { self.h64.guard_rf_failure_routine = v; } else { self.h32.guard_rf_failure_routine = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_rf_failure_routine_function_pointer(&self)
    => self.is64 ? self.h64.guard_rf_failure_routine_function_pointer : (ulong)self.h32.guard_rf_failure_routine_function_pointer;
fn void VipeViewLoadConfig.set_guard_rf_failure_routine_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_rf_failure_routine_function_pointer = v; } else { self.h32.guard_rf_failure_routine_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_rf_verify_stack_pointer_function_pointer(&self)
    => self.is64 ? self.h64.guard_rf_verify_stack_pointer_function_pointer : (ulong)self.h32.guard_rf_verify_stack_pointer_function_pointer;
fn void VipeViewLoadConfig.set_guard_rf_verify_stack_pointer_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_rf_verify_stack_pointer_function_pointer = v; } else { self.h32.guard_rf_verify_stack_pointer_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_enclave_configuration_pointer(&self)
    => self.is64 ? self.h64.enclave_configuration_pointer : (ulong)self.h32.enclave_configuration_pointer;
fn void VipeViewLoadConfig.set_enclave_configuration_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.enclave_configuration_pointer = v; } else { self.h32.enclave_configuration_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_volatile_metadata_pointer(&self)
    => self.is64 ? self.h64.volatile_metadata_pointer : (ulong)self.h32.volatile_metadata_pointer;
fn void VipeViewLoadConfig.set_volatile_metadata_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.volatile_metadata_pointer = v; } else { self.h32.volatile_metadata_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_eh_continuation_table(&self)
    => self.is64 ? self.h64.guard_eh_continuation_table : (ulong)self.h32.guard_eh_continuation_table;
fn void VipeViewLoadConfig.set_guard_eh_continuation_table(&self, ulong v)
{
    if (self.is64) { self.h64.guard_eh_continuation_table = v; } else { self.h32.guard_eh_continuation_table = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_eh_continuation_count(&self)
    => self.is64 ? self.h64.guard_eh_continuation_count : (ulong)self.h32.guard_eh_continuation_count;
fn void VipeViewLoadConfig.set_guard_eh_continuation_count(&self, ulong v)
{
    if (self.is64) { self.h64.guard_eh_continuation_count = v; } else { self.h32.guard_eh_continuation_count = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_xfg_check_function_pointer(&self)
    => self.is64 ? self.h64.guard_xfg_check_function_pointer : (ulong)self.h32.guard_xfg_check_function_pointer;
fn void VipeViewLoadConfig.set_guard_xfg_check_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_xfg_check_function_pointer = v; } else { self.h32.guard_xfg_check_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_xfg_dispatch_function_pointer(&self)
    => self.is64 ? self.h64.guard_xfg_dispatch_function_pointer : (ulong)self.h32.guard_xfg_dispatch_function_pointer;
fn void VipeViewLoadConfig.set_guard_xfg_dispatch_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_xfg_dispatch_function_pointer = v; } else { self.h32.guard_xfg_dispatch_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_xfg_table_dispatch_function_pointer(&self)
    => self.is64 ? self.h64.guard_xfg_table_dispatch_function_pointer : (ulong)self.h32.guard_xfg_table_dispatch_function_pointer;
fn void VipeViewLoadConfig.set_guard_xfg_table_dispatch_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_xfg_table_dispatch_function_pointer = v; } else { self.h32.guard_xfg_table_dispatch_function_pointer = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_cast_guard_os_determined_failure_mode(&self)
    => self.is64 ? self.h64.cast_guard_os_determined_failure_mode : (ulong)self.h32.cast_guard_os_determined_failure_mode;
fn void VipeViewLoadConfig.set_cast_guard_os_determined_failure_mode(&self, ulong v)
{
    if (self.is64) { self.h64.cast_guard_os_determined_failure_mode = v; } else { self.h32.cast_guard_os_determined_failure_mode = (uint)v; }
}

fn ulong VipeViewLoadConfig.get_guard_memcpy_function_pointer(&self)
    => self.is64 ? self.h64.guard_memcpy_function_pointer : (ulong)self.h32.guard_memcpy_function_pointer;
fn void VipeViewLoadConfig.set_guard_memcpy_function_pointer(&self, ulong v)
{
    if (self.is64) { self.h64.guard_memcpy_function_pointer = v; } else { self.h32.guard_memcpy_function_pointer = (uint)v; }
}
