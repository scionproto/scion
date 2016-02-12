#include "Path.h"
#include "PathPolicy.h"

PathPolicy::PathPolicy()
    : mStayISD(0)
{
}

PathPolicy::~PathPolicy()
{
}

void PathPolicy::setStayISD(uint16_t isd)
{
    mStayISD = isd;
}

bool PathPolicy::validate(Path *p)
{
    if (!mStayISD)
        return true;

    bool valid = true;
    valid = checkStayISD(p);
    DEBUG("path %d valid? %d\n", p->getIndex(), valid);
    return valid;
}

bool PathPolicy::checkStayISD(Path *p)
{
    std::vector<SCIONInterface> &ifs = p->getInterfaces();
    for (size_t i = 0; i < ifs.size(); i++) {
        SCIONInterface sif = ifs[i];
        if (sif.isd != mStayISD)
            return false;
    }
    return true;
}
