// SPDX-License-Identifier: AGPL-3.0-or-later

/// vat.sol -- Dai CDP database

// Copyright (C) 2018 Rain <rainbreak@riseup.net>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/**
## 描述
MakerDao的核心合约,没有任何外部依赖, 所有其他合约直接或间接调用该合约， 是DAI的会计不变式核心
内容：
1、包括了MakerDao协议状态和核心机制. eg: 内部Dai余额和抵押状态, 和相关的一些指标
2、它包含用于金库管理的公共接口，（金库）所有者调整其金库状态余额
3、提供Vault（金库）变更的相关接口，允许本人转出，分割、合并 （金库）

vat合约原则
1、 没有抵押品，Dai就不会存在
- ilk是一种特定的抵押品
- 通过slip方法修改gem数量，即抵押某种资产的数量
- 通过flux方法 转移抵押资产的所有权

2、 金库的数据结构是 Urn
- ink 担保抵押
- art 担保抵押的债务

3. 抵押品是 Ilk:
- Art 担保抵押的债务
- rate 债务比例系数
- spot 有安全边际的价格
- line 债务上限
- dust 最低债务


note:
wad - 18 decimal places
ray - 27 decimal places
rad - 45 decimal places

**/

pragma solidity >=0.5.12;

contract Vat {
    /**
        MakerDao 核心合约
        https://etherscan.io/address/0x35d1b3f3d7966a1dfe207aa4514c12a259a0492b
    **/

    // --- Auth --- 授权相关
    mapping (address => uint) public wards;  // 存储一个地址是否有权限访问需要授权的方法
    function rely(address usr) external note auth { require(live == 1, "Vat/not-live"); wards[usr] = 1; } // 给用户填权限
    function deny(address usr) external note auth { require(live == 1, "Vat/not-live"); wards[usr] = 0; } // 去除用户权限
    modifier auth {
        require(wards[msg.sender] == 1, "Vat/not-authorized");
        _;
    }

    mapping(address => mapping (address => uint)) public can;  // 检查一个地址是否能修改另一个地址的
    function hope(address usr) external note { can[msg.sender][usr] = 1; }
    function nope(address usr) external note { can[msg.sender][usr] = 0; }
    // 检查一个地址是否能修改另一个地址的 gem 或 dai
    function wish(address bit, address usr) internal view returns (bool) {
        return either(bit == usr, can[bit][usr] == 1);
    }

    // --- Data ---
    // 所有可抵押资产的相关属性参数
    struct Ilk {
        uint256 Art;   // Total Normalised Debt     [wad]  稳定币的总债务
        uint256 rate;  // Accumulated Rates         [ray]  稳定币的乘数比例
        uint256 spot;  // Price with Safety Margin  [ray]  比如:每种抵押物最大获取DAI的上限
        uint256 line;  // Debt Ceiling              [rad]  特定抵押品类型的债务上限
        uint256 dust;  // Urn Debt Floor            [rad]  CDP最小可能的债务
    }

    // 一个指定的CDP，eg: 用户用ETH抵押，换回DAI
    struct Urn {
        uint256 ink;   // Locked Collateral  [wad]  抵押的货币的数量 eg: 可抵押物的值
        uint256 art;   // Normalised Debt    [wad]  稳定币的总债务 eg: DAI
    }

    mapping (bytes32 => Ilk)                       public ilks;  // 所有的可抵押类型唯一标识和它的属性（配置）
    mapping (bytes32 => mapping (address => Urn )) public urns;  // 某种抵押资产下某个用户的抵押值和负债
    mapping (bytes32 => mapping (address => uint)) public gem;  // [wad] 某种资产类型下某个用户抵押代币
    mapping (address => uint256)                   public dai;  // [rad]
    mapping (address => uint256)                   public sin;  // [rad] 未抵押的稳定币, 不属于任何保险柜

    uint256 public debt;  // Total Dai Issued    [rad]  Dai合约发行的Dai流通数总和也就是系统的总的债务，因为只有抵押了才会产生Dai
    uint256 public vice;  // Total Unbacked Dai  [rad]  is the sum of all sin (the total quantity of system debt).
    uint256 public Line;  // Total Debt Ceiling  [rad]  抵押品的债务上限
    uint256 public live;  // Active Flag         标识合约可调用， 创建合约时候变1， 合约创建者可以设置为0变不可用

    // --- Logs ---
    event LogNote(
        bytes4   indexed  sig,
        bytes32  indexed  arg1,
        bytes32  indexed  arg2,
        bytes32  indexed  arg3,
        bytes             data
    ) anonymous;

    modifier note {
        _;
        assembly {
            // log an 'anonymous' event with a constant 6 words of calldata
            // and four indexed topics: the selector and the first three args
            let mark := msize()                       // end of memory ensures zero
            mstore(0x40, add(mark, 288))              // update free memory pointer
            mstore(mark, 0x20)                        // bytes type data offset
            mstore(add(mark, 0x20), 224)              // bytes size (padded)
            calldatacopy(add(mark, 0x40), 0, 224)     // bytes payload
            log4(mark, 288,                           // calldata
                 shl(224, shr(224, calldataload(0))), // msg.sig
                 calldataload(4),                     // arg1
                 calldataload(36),                    // arg2
                 calldataload(68)                     // arg3
                )
        }
    }

    // --- Init ---
    // 当第一次创建合约, 把当前人发布合约的人方法权限设置1， 并标记合约live=1表示已上线
    constructor() public {
        wards[msg.sender] = 1;
        live = 1;
    }

    // --- Math ---
    function add(uint x, int y) internal pure returns (uint z) {
        z = x + uint(y);
        require(y >= 0 || z <= x);
        require(y <= 0 || z >= x);
    }
    function sub(uint x, int y) internal pure returns (uint z) {
        z = x - uint(y);
        require(y <= 0 || z <= x);
        require(y >= 0 || z >= x);
    }
    function mul(uint x, int y) internal pure returns (int z) {
        z = int(x) * y;
        require(int(x) >= 0);
        require(y == 0 || z / y == int(x));
    }
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x);
    }

    // --- Administration --- 管理员相关操作
    // 创建一个新的抵押类型
    function init(bytes32 ilk) external note auth {
        require(ilks[ilk].rate == 0, "Vat/ilk-already-init");
        ilks[ilk].rate = 10 ** 27;
    }

    // 修改抵押品的债务上限
    function file(bytes32 what, uint data) external note auth {
        require(live == 1, "Vat/not-live");
        if (what == "Line") Line = data;
        else revert("Vat/file-unrecognized-param");
    }

    // 修改单个资产可抵押资产的的一些属性
    function file(bytes32 ilk, bytes32 what, uint data) external note auth {
        require(live == 1, "Vat/not-live");
        if (what == "spot") ilks[ilk].spot = data;
        else if (what == "line") ilks[ilk].line = data;
        else if (what == "dust") ilks[ilk].dust = data;
        else revert("Vat/file-unrecognized-param");
    }

    // 使当前合约不可调用
    function cage() external note auth {
        live = 0;
    }

    // --- Fungibility ---
    // 修改某种资产下某用户的抵押值（balance）
    function slip(bytes32 ilk, address usr, int256 wad) external note auth {
        gem[ilk][usr] = add(gem[ilk][usr], wad);
    }

    // 用户之间转移抵押数量 把自己的抵押资产给别人
    function flux(bytes32 ilk, address src, address dst, uint256 wad) external note {
        require(wish(src, msg.sender), "Vat/not-allowed");
        gem[ilk][src] = sub(gem[ilk][src], wad);  // 原来的减少
        gem[ilk][dst] = add(gem[ilk][dst], wad);  // 目的地址增加相同的数量
    }

    // 用户之间转移稳定币DAI
    function move(address src, address dst, uint256 rad) external note {
        require(wish(src, msg.sender), "Vat/not-allowed");
        dai[src] = sub(dai[src], rad);  // 原来的减少
        dai[dst] = add(dai[dst], rad);  // 目的地址增加相同的数量
    }

    function either(bool x, bool y) internal pure returns (bool z) {
        assembly{ z := or(x, y)}
    }
    function both(bool x, bool y) internal pure returns (bool z) {
        assembly{ z := and(x, y)}
    }

    // --- CDP Manipulation ---
    /**修改保险箱 eg: 在其他合约中的方法，最终会调用 vat 的frob
    lock: 抵押资产到保险箱
    free: 相当与unlock这个资产从保险箱
    draw: 增加保险柜债务，创建Dai
    wipe: 减少保险柜债务，销毁Dai
    dink: 抵押品变更
    dart: 债务变动
    **/
    function frob(bytes32 i, address u, address v, address w, int dink, int dart) external note {
        // 通过用户v的gem和为用户创建DAI来修改用户u的资产
        // system is live
        require(live == 1, "Vat/not-live");

        Urn memory urn = urns[i][u];  // 取出某个可抵押资产下某个用户的 抵押和负债值
        Ilk memory ilk = ilks[i];     // 取出当前用到的可抵押资产的某个
        // ilk has been initialised
        require(ilk.rate != 0, "Vat/ilk-not-init");

        urn.ink = add(urn.ink, dink);  // 增加抵押
        urn.art = add(urn.art, dart);  // 增加稳定币债务
        ilk.Art = add(ilk.Art, dart);  // 某种资产的总债务

        int dtab = mul(ilk.rate, dart);
        uint tab = mul(ilk.rate, urn.art);
        debt     = add(debt, dtab);

        // either debt has decreased, or debt ceilings are not exceeded
        require(either(dart <= 0, both(mul(ilk.Art, ilk.rate) <= ilk.line, debt <= Line)), "Vat/ceiling-exceeded");
        // urn is either less risky than before, or it is safe
        require(either(both(dart <= 0, dink >= 0), tab <= mul(urn.ink, ilk.spot)), "Vat/not-safe");

        // urn is either more safe, or the owner consents
        require(either(both(dart <= 0, dink >= 0), wish(u, msg.sender)), "Vat/not-allowed-u");
        // collateral src consents
        require(either(dink <= 0, wish(v, msg.sender)), "Vat/not-allowed-v");
        // debt dst consents
        require(either(dart >= 0, wish(w, msg.sender)), "Vat/not-allowed-w");

        // urn has no debt, or a non-dusty amount
        require(either(urn.art == 0, tab >= ilk.dust), "Vat/dust");

        gem[i][v] = sub(gem[i][v], dink);
        dai[w]    = add(dai[w],    dtab);

        urns[i][u] = urn;
        ilks[i]    = ilk;
    }
    // --- CDP Fungibility ---
    /**拆分合并保险柜
    dink: 改为抵押物数量
    dart: 要交换的稳定币债务金额
    **/
    function fork(bytes32 ilk, address src, address dst, int dink, int dart) external note {
        Urn storage u = urns[ilk][src];
        Urn storage v = urns[ilk][dst];
        Ilk storage i = ilks[ilk];

        u.ink = sub(u.ink, dink);
        u.art = sub(u.art, dart);
        v.ink = add(v.ink, dink);
        v.art = add(v.art, dart);

        uint utab = mul(u.art, i.rate);
        uint vtab = mul(v.art, i.rate);

        // both sides consent
        require(both(wish(src, msg.sender), wish(dst, msg.sender)), "Vat/not-allowed");

        // both sides safe
        require(utab <= mul(u.ink, i.spot), "Vat/not-safe-src");
        require(vtab <= mul(v.ink, i.spot), "Vat/not-safe-dst");

        // both sides non-dusty
        require(either(utab >= i.dust, u.art == 0), "Vat/dust-src");
        require(either(vtab >= i.dust, v.art == 0), "Vat/dust-dst");
    }
    // --- CDP Confiscation ---
    // 清算保险箱
    function grab(bytes32 i, address u, address v, address w, int dink, int dart) external note auth {
        Urn storage urn = urns[i][u];
        Ilk storage ilk = ilks[i];

        urn.ink = add(urn.ink, dink);
        urn.art = add(urn.art, dart);
        ilk.Art = add(ilk.Art, dart);

        int dtab = mul(ilk.rate, dart);

        gem[i][v] = sub(gem[i][v], dink);
        sin[w]    = sub(sin[w],    dtab);
        vice      = sub(vice,      dtab);
    }

    // --- Settlement ---
    // 创建或销毁等价的稳定币和系统债务
    function heal(uint rad) external note {
        address u = msg.sender;
        sin[u] = sub(sin[u], rad);
        dai[u] = sub(dai[u], rad);
        vice   = sub(vice,   rad);
        debt   = sub(debt,   rad);
    }

    // 挖矿 无抵押的稳定币
    function suck(address u, address v, uint rad) external note auth {
        sin[u] = add(sin[u], rad);
        dai[v] = add(dai[v], rad);
        vice   = add(vice,   rad);
        debt   = add(debt,   rad);
    }

    // --- Rates ---
    function fold(bytes32 i, address u, int rate) external note auth {
        require(live == 1, "Vat/not-live");
        Ilk storage ilk = ilks[i];
        ilk.rate = add(ilk.rate, rate);
        int rad  = mul(ilk.Art, rate);
        dai[u]   = add(dai[u], rad);
        debt     = add(debt,   rad);
    }
}
