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

macro uint VipeViewLoadConfig.size(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.size, self.h32.size, v);

macro uint VipeViewLoadConfig.time_date_stamp(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.time_date_stamp, self.h32.time_date_stamp, v);

macro ushort VipeViewLoadConfig.major_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.h64.major_version, self.h32.major_version, v);

macro ushort VipeViewLoadConfig.minor_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.h64.minor_version, self.h32.minor_version, v);

macro uint VipeViewLoadConfig.global_flags_clear(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.global_flags_clear, self.h32.global_flags_clear, v);

macro uint VipeViewLoadConfig.global_flags_set(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.global_flags_set, self.h32.global_flags_set, v);

macro uint VipeViewLoadConfig.critical_section_default_timeout(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.critical_section_default_timeout, self.h32.critical_section_default_timeout, v);

macro uint VipeViewLoadConfig.process_heap_flags(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.process_heap_flags, self.h32.process_heap_flags, v);

macro ushort VipeViewLoadConfig.csd_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.h64.csd_version, self.h32.csd_version, v);

macro ushort VipeViewLoadConfig.dependent_load_flags(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.h64.dependent_load_flags, self.h32.dependent_load_flags, v);

macro uint VipeViewLoadConfig.guard_flags(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.guard_flags, self.h32.guard_flags, v);

// ulong fields (uint in 32, ulong in 64)

macro ulong VipeViewLoadConfig.de_commit_free_block_threshold(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.de_commit_free_block_threshold, v)
        : common::@exchange(self.h32.de_commit_free_block_threshold, (uint)v);

macro ulong VipeViewLoadConfig.de_commit_total_free_threshold(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.de_commit_total_free_threshold, v)
        : common::@exchange(self.h32.de_commit_total_free_threshold, (uint)v);

macro ulong VipeViewLoadConfig.lock_prefix_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.lock_prefix_table, v)
        : common::@exchange(self.h32.lock_prefix_table, (uint)v);

macro ulong VipeViewLoadConfig.maximum_allocation_size(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.maximum_allocation_size, v)
        : common::@exchange(self.h32.maximum_allocation_size, (uint)v);

macro ulong VipeViewLoadConfig.virtual_memory_threshold(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.virtual_memory_threshold, v)
        : common::@exchange(self.h32.virtual_memory_threshold, (uint)v);

macro ulong VipeViewLoadConfig.process_affinity_mask(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.process_affinity_mask, v)
        : common::@exchange(self.h32.process_affinity_mask, (uint)v);

macro ulong VipeViewLoadConfig.edit_list(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.edit_list, v)
        : common::@exchange(self.h32.edit_list, (uint)v);

macro ulong VipeViewLoadConfig.security_cookie(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.security_cookie, v)
        : common::@exchange(self.h32.security_cookie, (uint)v);

macro ulong VipeViewLoadConfig.se_handler_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.se_handler_table, v)
        : common::@exchange(self.h32.se_handler_table, (uint)v);

macro ulong VipeViewLoadConfig.se_handler_count(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.se_handler_count, v)
        : common::@exchange(self.h32.se_handler_count, (uint)v);

macro ulong VipeViewLoadConfig.guard_cf_check_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_cf_check_function_pointer, v)
        : common::@exchange(self.h32.guard_cf_check_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_cf_dispatch_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_cf_dispatch_function_pointer, v)
        : common::@exchange(self.h32.guard_cf_dispatch_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_cf_function_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_cf_function_table, v)
        : common::@exchange(self.h32.guard_cf_function_table, (uint)v);

macro ulong VipeViewLoadConfig.guard_cf_function_count(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_cf_function_count, v)
        : common::@exchange(self.h32.guard_cf_function_count, (uint)v);

macro ulong VipeViewLoadConfig.guard_address_taken_iat_entry_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_address_taken_iat_entry_table, v)
        : common::@exchange(self.h32.guard_address_taken_iat_entry_table, (uint)v);

macro ulong VipeViewLoadConfig.guard_address_taken_iat_entry_count(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_address_taken_iat_entry_count, v)
        : common::@exchange(self.h32.guard_address_taken_iat_entry_count, (uint)v);

macro ulong VipeViewLoadConfig.guard_long_jump_target_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_long_jump_target_table, v)
        : common::@exchange(self.h32.guard_long_jump_target_table, (uint)v);

macro ulong VipeViewLoadConfig.guard_long_jump_target_count(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_long_jump_target_count, v)
        : common::@exchange(self.h32.guard_long_jump_target_count, (uint)v);

macro ulong VipeViewLoadConfig.guard_rf_failure_routine(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_rf_failure_routine, v)
        : common::@exchange(self.h32.guard_rf_failure_routine, (uint)v);

macro ulong VipeViewLoadConfig.guard_rf_failure_routine_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_rf_failure_routine_function_pointer, v)
        : common::@exchange(self.h32.guard_rf_failure_routine_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_rf_verify_stack_pointer_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_rf_verify_stack_pointer_function_pointer, v)
        : common::@exchange(self.h32.guard_rf_verify_stack_pointer_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.enclave_configuration_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.enclave_configuration_pointer, v)
        : common::@exchange(self.h32.enclave_configuration_pointer, (uint)v);

macro ulong VipeViewLoadConfig.volatile_metadata_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.volatile_metadata_pointer, v)
        : common::@exchange(self.h32.volatile_metadata_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_eh_continuation_table(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_eh_continuation_table, v)
        : common::@exchange(self.h32.guard_eh_continuation_table, (uint)v);

macro ulong VipeViewLoadConfig.guard_eh_continuation_count(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_eh_continuation_count, v)
        : common::@exchange(self.h32.guard_eh_continuation_count, (uint)v);

macro ulong VipeViewLoadConfig.guard_xfg_check_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_xfg_check_function_pointer, v)
        : common::@exchange(self.h32.guard_xfg_check_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_xfg_dispatch_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_xfg_dispatch_function_pointer, v)
        : common::@exchange(self.h32.guard_xfg_dispatch_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.guard_xfg_table_dispatch_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_xfg_table_dispatch_function_pointer, v)
        : common::@exchange(self.h32.guard_xfg_table_dispatch_function_pointer, (uint)v);

macro ulong VipeViewLoadConfig.cast_guard_os_determined_failure_mode(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.cast_guard_os_determined_failure_mode, v)
        : common::@exchange(self.h32.cast_guard_os_determined_failure_mode, (uint)v);

macro ulong VipeViewLoadConfig.guard_memcpy_function_pointer(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.h64.guard_memcpy_function_pointer, v)
        : common::@exchange(self.h32.guard_memcpy_function_pointer, (uint)v);
