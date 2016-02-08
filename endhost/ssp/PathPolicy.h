#ifndef PATH_POLICY_H
#define PATH_POLICY_H

#include <vector>

#include "SCIONDefines.h"

class Path;

class PathPolicy {
public:
    PathPolicy();
    ~PathPolicy();

    void setStayISD(uint16_t isd);

    bool validate(Path *p);

protected:
    bool checkStayISD(Path *p);

    uint16_t mStayISD;
    std::vector<uint16_t> mAvoidISDs;
    std::vector<uint32_t> mAvoidADs;
};

#endif
