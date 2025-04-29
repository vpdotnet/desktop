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

#include "split_tunnel_types.h"
#include <kapps_core/src/stringslice.h>

// PF rules for split tunnel network paths
const kapps::core::StringSlice kVpnOnlyApps4{"vpnonly4"};
const kapps::core::StringSlice kVpnOnlyApps6{"vpnonly6"};
const kapps::core::StringSlice kBypassApps4{"bypass4"};
const kapps::core::StringSlice kBypassApps6{"bypass6"};
const kapps::core::StringSlice kDefaultApps4{"default4"};
const kapps::core::StringSlice kDefaultApps6{"default6"};