#ifndef PATH_POLICY_H
#define PATH_POLICY_H

#include <set>
#include <vector>

#include "SCIONDefines.h"

class Path;

class PathPolicy {
public:
    PathPolicy();
    ~PathPolicy();

    void setISDWhitelist(std::vector<uint16_t> &isds);

    bool validate(Path *p);

protected:
    bool isWhitelisted(Path *p);

    std::set<uint16_t> mWhitelist;
    std::vector<uint16_t> mAvoidISDs;
    std::vector<uint32_t> mAvoidADs;
};

#endif
