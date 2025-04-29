// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#pragma once
#include <set>
#include <cstdint>
#include <string>
#include <kapps_core/src/stringslice.h>

namespace kapps { namespace net {

enum IPVersion 
{
    IPv4,
    IPv6
};

using PortSet = std::set<std::uint16_t>;

// Utility functions needed by dependent code
inline std::string ipToString(IPVersion ipVersion) {
    return ipVersion == IPv4 ? "IPv4" : "IPv6";
}

}} // namespace kapps::net

// PF rules for split tunnel network paths
extern const kapps::core::StringSlice kVpnOnlyApps4;
extern const kapps::core::StringSlice kVpnOnlyApps6;
extern const kapps::core::StringSlice kBypassApps4;
extern const kapps::core::StringSlice kBypassApps6;
extern const kapps::core::StringSlice kDefaultApps4;
extern const kapps::core::StringSlice kDefaultApps6;