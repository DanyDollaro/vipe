module ope::common;

faultdef
    SIGNATURE_MISMATCH,
    MISSING_RESOURCE,
    TRUNCATED_DATA,
    UNABLE_TO_RESOLVE,
    EXPORTED_BY_ORDINAL;

macro @exchange(#self, #val = ...)
{
    $if $defined(val):
        var old = #self;
        #self = #val;
        return old;
    $else
        return #self;
    $endif
}

macro extract_struct($Type, char[] buffer)
{
    if (buffer.len < $Type::size) return common::TRUNCATED_DATA~;
    return ($Type*)buffer.ptr;
}
