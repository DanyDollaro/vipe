module vipe::common;

faultdef
    INVALID_PE,
    MISSING_RESOURCE,
    NOT_ENOUGH_DATA,
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

macro @select_exchange(bool condition, #field1, #field2, #val = ...)
{
    $if $defined(val):
        return condition
            ? @exchange(#field1, #val)
            : @exchange(#field2, #val);
    $else
        return condition
            ? #field1
            : #field2;
    $endif
}

macro extract_struct($Type, char[] buffer)
{
    if (buffer.len < $Type::size)
    {
        return common::NOT_ENOUGH_DATA~;
    }

    return ($Type*)buffer.ptr;
}


fn bool is_zero_struct(void* ptr, sz size)
{
    for (sz i = 0; i < size; i++)
    {
        if (*(char*)ptr)
        {
            return false;
        }
    }

    return true;
}
