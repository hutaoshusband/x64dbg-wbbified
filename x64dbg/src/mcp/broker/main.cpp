#include "bootstrap.h"

int wmain(int argc, wchar_t** argv)
{
    return wininspect::mcp::native_component_main(wininspect::mcp::NativeComponent::Broker, argc, argv);
}
