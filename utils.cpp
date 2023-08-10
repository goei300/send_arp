#include "utils.h"
#include <sstream>

bool isValidIP(const std::string& ip) {
    std::istringstream iss(ip);
    std::string segment;
    int count = 0, value;

    while (std::getline(iss, segment, '.')) {
        count++;

        std::istringstream issSegment(segment);
        issSegment >> value;

        if (segment.empty() || value < 0 || value > 255 || (issSegment.peek() != EOF))
            return false;
    }

    return count == 4;
}
