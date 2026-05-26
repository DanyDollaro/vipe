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

macro extract_struct($Type, char[] buffer)
{
    if (buffer.len < $Type::size)
    {
        return common::NOT_ENOUGH_DATA~;
    }

    return ($Type*)buffer.ptr;
}

