module ope::load_config;
import ope::common;

struct OpeRawLoadConfig32 @packed
{
    uint   size;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   global_flags_clear;
    uint   global_flags_set;
    uint   critical_section_default_timeout;
    uint   de_commit_free_block_threshold;
    uint   de_commit_total_free_threshold;
    uint   lock_prefix_table;
    uint   maximum_allocation_size;
    uint   virtual_memory_threshold;
    uint   process_affinity_mask;
    uint   process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    uint   edit_list;
    uint   security_cookie;
    uint   se_handler_table;
    uint   se_handler_count;
    uint   guard_cf_check_function_pointer;
    uint   guard_cf_dispatch_function_pointer;
    uint   guard_cf_function_table;
    uint   guard_cf_function_count;
    uint   guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint   ci_catalog_offset;
    uint   ci_reserved;
    uint   guard_address_taken_iat_entry_table;
    uint   guard_address_taken_iat_entry_count;
    uint   guard_long_jump_target_table;
    uint   guard_long_jump_target_count;
    uint   dynamic_value_reloc_table;
    uint   chpe_metadata_pointer;
    uint   guard_rf_failure_routine;
    uint   guard_rf_failure_routine_function_pointer;
    uint   dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    uint   guard_rf_verify_stack_pointer_function_pointer;
    uint   hot_patch_table_offset;
    uint   reserved3;
    uint   enclave_configuration_pointer;
    uint   volatile_metadata_pointer;
    uint   guard_eh_continuation_table;
    uint   guard_eh_continuation_count;
    uint   guard_xfg_check_function_pointer;
    uint   guard_xfg_dispatch_function_pointer;
    uint   guard_xfg_table_dispatch_function_pointer;
    uint   cast_guard_os_determined_failure_mode;
    uint   guard_memcpy_function_pointer;
}

struct OpeRawLoadConfig64 @packed
{
    uint   size;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   global_flags_clear;
    uint   global_flags_set;
    uint   critical_section_default_timeout;
    ulong  de_commit_free_block_threshold;
    ulong  de_commit_total_free_threshold;
    ulong  lock_prefix_table;
    ulong  maximum_allocation_size;
    ulong  virtual_memory_threshold;
    ulong  process_affinity_mask;
    uint   process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    ulong  edit_list;
    ulong  security_cookie;
    ulong  se_handler_table;
    ulong  se_handler_count;
    ulong  guard_cf_check_function_pointer;
    ulong  guard_cf_dispatch_function_pointer;
    ulong  guard_cf_function_table;
    ulong  guard_cf_function_count;
    uint   guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint   ci_catalog_offset;
    uint   ci_reserved;
    ulong  guard_address_taken_iat_entry_table;
    ulong  guard_address_taken_iat_entry_count;
    ulong  guard_long_jump_target_table;
    ulong  guard_long_jump_target_count;
    ulong  dynamic_value_reloc_table;
    ulong  chpe_metadata_pointer;
    ulong  guard_rf_failure_routine;
    ulong  guard_rf_failure_routine_function_pointer;
    uint   dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    ulong  guard_rf_verify_stack_pointer_function_pointer;
    uint   hot_patch_table_offset;
    uint   reserved3;
    ulong  enclave_configuration_pointer;
    ulong  volatile_metadata_pointer;
    ulong  guard_eh_continuation_table;
    ulong  guard_eh_continuation_count;
    ulong  guard_xfg_check_function_pointer;
    ulong  guard_xfg_dispatch_function_pointer;
    ulong  guard_xfg_table_dispatch_function_pointer;
    ulong  cast_guard_os_determined_failure_mode;
    ulong  guard_memcpy_function_pointer;
}

struct OpeViewLoadConfig
{
    bool is64;
    union
    {
        OpeRawLoadConfig32* h32;
        OpeRawLoadConfig64* h64;
    }
}

macro uint OpeViewLoadConfig.size(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size : self.h32.size, v);

macro uint OpeViewLoadConfig.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.time_date_stamp : self.h32.time_date_stamp, v);

macro ushort OpeViewLoadConfig.major_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.major_version : self.h32.major_version, v);

macro ushort OpeViewLoadConfig.minor_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.minor_version : self.h32.minor_version, v);

macro uint OpeViewLoadConfig.global_flags_clear(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.global_flags_clear : self.h32.global_flags_clear, v);

macro uint OpeViewLoadConfig.global_flags_set(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.global_flags_set : self.h32.global_flags_set, v);

macro uint OpeViewLoadConfig.critical_section_default_timeout(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.critical_section_default_timeout : self.h32.critical_section_default_timeout, v);

macro ulong OpeViewLoadConfig.de_commit_free_block_threshold(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.de_commit_free_block_threshold : (ulong)self.h32.de_commit_free_block_threshold, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.de_commit_total_free_threshold(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.de_commit_total_free_threshold : (ulong)self.h32.de_commit_total_free_threshold, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.lock_prefix_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.lock_prefix_table : (ulong)self.h32.lock_prefix_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.maximum_allocation_size(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.maximum_allocation_size : (ulong)self.h32.maximum_allocation_size, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.virtual_memory_threshold(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.virtual_memory_threshold : (ulong)self.h32.virtual_memory_threshold, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.process_affinity_mask(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.process_affinity_mask : (ulong)self.h32.process_affinity_mask, self.is64 ? v : (uint)v);

macro uint OpeViewLoadConfig.process_heap_flags(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.process_heap_flags : self.h32.process_heap_flags, v);

macro ushort OpeViewLoadConfig.csd_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.csd_version : self.h32.csd_version, v);

macro ushort OpeViewLoadConfig.dependent_load_flags(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.dependent_load_flags : self.h32.dependent_load_flags, v);

macro ulong OpeViewLoadConfig.edit_list(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.edit_list : (ulong)self.h32.edit_list, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.security_cookie(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.security_cookie : (ulong)self.h32.security_cookie, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.se_handler_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.se_handler_table : (ulong)self.h32.se_handler_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.se_handler_count(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.se_handler_count : (ulong)self.h32.se_handler_count, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_cf_check_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_cf_check_function_pointer : (ulong)self.h32.guard_cf_check_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_cf_dispatch_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_cf_dispatch_function_pointer : (ulong)self.h32.guard_cf_dispatch_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_cf_function_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_cf_function_table : (ulong)self.h32.guard_cf_function_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_cf_function_count(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_cf_function_count : (ulong)self.h32.guard_cf_function_count, self.is64 ? v : (uint)v);

macro uint OpeViewLoadConfig.guard_flags(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_flags : self.h32.guard_flags, v);

macro ulong OpeViewLoadConfig.guard_address_taken_iat_entry_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_address_taken_iat_entry_table : (ulong)self.h32.guard_address_taken_iat_entry_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_address_taken_iat_entry_count(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_address_taken_iat_entry_count : (ulong)self.h32.guard_address_taken_iat_entry_count, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_long_jump_target_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_long_jump_target_table : (ulong)self.h32.guard_long_jump_target_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_long_jump_target_count(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_long_jump_target_count : (ulong)self.h32.guard_long_jump_target_count, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_rf_failure_routine(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_rf_failure_routine : (ulong)self.h32.guard_rf_failure_routine, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_rf_failure_routine_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_rf_failure_routine_function_pointer : (ulong)self.h32.guard_rf_failure_routine_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_rf_verify_stack_pointer_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_rf_verify_stack_pointer_function_pointer : (ulong)self.h32.guard_rf_verify_stack_pointer_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.enclave_configuration_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.enclave_configuration_pointer : (ulong)self.h32.enclave_configuration_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.volatile_metadata_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.volatile_metadata_pointer : (ulong)self.h32.volatile_metadata_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_eh_continuation_table(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_eh_continuation_table : (ulong)self.h32.guard_eh_continuation_table, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_eh_continuation_count(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_eh_continuation_count : (ulong)self.h32.guard_eh_continuation_count, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_xfg_check_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_xfg_check_function_pointer : (ulong)self.h32.guard_xfg_check_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_xfg_dispatch_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_xfg_dispatch_function_pointer : (ulong)self.h32.guard_xfg_dispatch_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_xfg_table_dispatch_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_xfg_table_dispatch_function_pointer : (ulong)self.h32.guard_xfg_table_dispatch_function_pointer, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.cast_guard_os_determined_failure_mode(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.cast_guard_os_determined_failure_mode : (ulong)self.h32.cast_guard_os_determined_failure_mode, self.is64 ? v : (uint)v);

macro ulong OpeViewLoadConfig.guard_memcpy_function_pointer(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.guard_memcpy_function_pointer : (ulong)self.h32.guard_memcpy_function_pointer, self.is64 ? v : (uint)v);
