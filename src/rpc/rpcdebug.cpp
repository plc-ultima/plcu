//******************************************************************************
//******************************************************************************

#include "consensus/validation.h"
#include "rpc/rpcserver.h"
#include "utilstrencodings.h"


//******************************************************************************
//******************************************************************************
static const CRPCCommand commands[] =
{ //  category    name                     actor (function)        okSafeMode
  //  ----------  --------------------     ------------------      ----------
};

//******************************************************************************
//******************************************************************************
void RegisterDebugRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
    {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
