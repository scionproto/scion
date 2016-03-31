#include "Path.h"
#include "PathPolicy.h"

PathPolicy::PathPolicy()
{
}

PathPolicy::~PathPolicy()
{
}

void PathPolicy::setISDWhitelist(std::vector<uint16_t> &isds)
{
    if (isds.empty())
        mWhitelist.clear();

    for (size_t i = 0; i < isds.size(); i++)
        mWhitelist.insert(isds[i]);
}

bool PathPolicy::validate(Path *p)
{
    if (!mWhitelist.empty() && !isWhitelisted(p))
        goto FAIL;

    return true;
FAIL:
    DEBUG("path %d invalid\n", p->getIndex());
    return false;
}

bool PathPolicy::isWhitelisted(Path *p)
{
    std::vector<SCIONInterface> &ifs = p->getInterfaces();
    for (size_t i = 0; i < ifs.size(); i++) {
        SCIONInterface sif = ifs[i];
        if (mWhitelist.find(sif.isd) == mWhitelist.end())
            return false;
    }
    return true;
}
