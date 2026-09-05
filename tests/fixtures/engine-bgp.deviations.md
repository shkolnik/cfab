# `engine-bgp.json` — shape, naming, and the citation for every leaf

Companion to `tests/fixtures/engine-bgp.json`. JSON carries no comments, so the proof that each
leaf exists **and is not deviated `not-supported`** lives here.

Every `<file>:<line>` below is in the holo fork at `/workspaces/ibgp/holo`, branch `bgp-gate2`
(`d0af28dc`), which is what `holo.rev` pins.

## 1. The document shape

The fixture is not a whole engine tree: it is the BGP + routing-policy material that
`src/emit/engine.rs::generate_at` must **add to** the document it already builds. Two top-level
keys:

| fixture key | where it goes in the emitted document |
|---|---|
| `ietf-routing-policy:routing-policy` | a new top-level key of the emitted object, beside `ietf-interfaces:interfaces` and `ietf-routing:routing` |
| `bgp-instance` | **fixture-only wrapper.** Its value is one more element appended to `ietf-routing:routing / control-plane-protocols / control-plane-protocol` (the array that already holds the per-zone `ietf-ospf:ospfv2` instances). The key `bgp-instance` never appears in the emitted document. |

So the E1.2 test reads:

```rust
assert_eq!(
    emitted["ietf-routing-policy:routing-policy"],
    fixture["ietf-routing-policy:routing-policy"]
);
assert_eq!(bgp_instance(emitted), fixture["bgp-instance"]);
```

where `bgp_instance()` picks the single `control-plane-protocol` element whose `type` is
`ietf-bgp:bgp`.

Order matters for `assert_eq!` on `Value`: arrays are compared element-wise. The fixture's order is
the emitter's contract — neighbors in gw-row order (`View::gw_rows()`, ZONE_TABLE order), prefix
sets and policy definitions in gw-zone order, and within a zone the import policy before the export
policy.

## 2. Naming convention

`src/emit/policy.rs` and `src/emit/mark.rs` name generated nft objects after the declaration:
tables are `cfab` / `cfab-fwd` (`src/emit/mark.rs:124`, `src/emit/policy.rs:13`) and sets are the
bare zone name (`src/emit/policy.rs:29`). Interfaces are `cfab-<kind><zone-id>`
(`cfab-id249`, `cfab-gw249`). OSPF instances are named by zone because there is one per zone
(`src/emit/engine.rs`, `"name": z.name`).

This subtree follows the same rule, prefixing every *globally scoped* name with `cfab-` because
routing-policy names live in one flat, fabric-wide namespace:

| object | spelling | example (member `pve1-tb`) |
|---|---|---|
| BGP instance (`control-plane-protocol/name`) | `cfab` | `cfab` |
| identity prefix set | `cfab-<zone>-id` | `cfab-mgmt-id` |
| global import policy, per gw zone | `cfab-<zone>-import` | `cfab-mgmt-import` |
| neighbor export policy, per gw zone | `cfab-<zone>-export` | `cfab-mgmt-export` |
| policy statement | `1` | `1` |

The BGP instance is **not** named after a zone: there is exactly one per member and it carries a
neighbor per gw zone, so a zone name would be a lie the moment a second zone declares a `gw`. `cfab`
matches the main nft table. Statement names follow holo's own convention (`"1"`), leaving room for
ordered numbering — holo keys statements in a `BTreeMap` by name, so the name *is* the order.

## 3. Derived values (member `pve1-tb` of `examples/fabric.conf`)

Printed by a throwaway `cargo test` against the real parser, not inferred:

```
MEMBER pve1-tb node=1 kind=Host
  GW if=cfab-gw249 home=eth0 zone=mgmt vid=249 migrates=false
     leg=192.168.249.1/24 router=192.168.249.254 block=10.249
     ident=10.249.0.1 identif=cfab-id249
AS=65000 hold=3 keepalive=1 connect=3
```

`pve1-tb` is the only member with the mgmt gw row *and* node 1; `pve2-tb` differs only in the
leg address (`192.168.249.2`) and router-id (`10.249.0.2`), and `pve3-tb` is a leaf and emits
nothing here (`derive.rs:305` — `gw_rows_of` returns empty for a non-host).

| value | source |
|---|---|
| `as: 65000` | `BGP_AS=65000` in `examples/fabric.conf`, parsed to `Fabric::bgp_as` |
| `identifier: "10.249.0.1"` | `View::identity_addr(mgmt)` = `10.<id>.0.<node>` (`src/derive.rs:214`), first gw zone in ZONE_TABLE order |
| `remote-address: "192.168.249.254"` | `ZoneGw::router` (`src/model.rs:182`) |
| `peer-as: 65000` | same AS = iBGP |
| `transport/local-address: "192.168.249.1"` | `ZoneGw::leg_cidr(1)` (`src/model.rs:195`) minus `/24` |
| `hold-time: 3`, `keepalive: 1`, `connect-retry-interval: 3` | `BGP_HOLD_S` / `BGP_KEEPALIVE_S` / `BGP_CONNECT_S` |
| `ip-prefix: "10.249.0.0/24"` | `Zone::block()` = `10.<id>` (`src/model.rs:235`) + `.0.0/24` |

## 4. Leaf-by-leaf citations

Schema files are under `holo-yang/modules/`; `ietf/` and `augmentations/` and `deviations/` are
elided below where the file name already says which.

### `ietf-routing-policy:routing-policy`

| yang path | proof it exists | proof it is supported (holo binding) |
|---|---|---|
| `/routing-policy` | `ietf/ietf-routing-policy@2021-10-11.yang:551` | module in `implemented_modules::POLICY`, `holo-yang/src/lib.rs:317` |
| `…/defined-sets` | `ietf-routing-policy@2021-10-11.yang:554` | — |
| `…/defined-sets/prefix-sets` | `:558` | — |
| `…/prefix-sets/prefix-set` (key `name mode`) | `:562` | `holo-policy/src/northbound/configuration.rs:43`, `:80` |
| `…/prefix-set/name` | `:566` | key |
| `…/prefix-set/mode` (`ipv4`) | `:572` | key; `PrefixSet.mode: AddressFamily`, `holo-utils/src/policy.rs:152` |
| `…/prefix-set/prefixes` | `:591` | — |
| `…/prefixes/prefix-list` (key `ip-prefix mask-length-lower mask-length-upper`) | `:600`, grouping `prefix` at `:403` | `holo-policy/src/northbound/configuration.rs:110` (`apply_prefix_list`), `:112` Create |
| `…/prefix-list/ip-prefix` | `:426` | `IpPrefixRange.prefix`, `holo-utils/src/policy.rs:109` |
| `…/prefix-list/mask-length-lower` (`32`) | `:436` | `IpPrefixRange.masklen_lower`, `holo-utils/src/policy.rs:110` |
| `…/prefix-list/mask-length-upper` (`32`) | `:444`, `must` upper >= lower | `IpPrefixRange.masklen_upper`, `holo-utils/src/policy.rs:111` |
| `…/policy-definitions` | `:652` | — |
| `…/policy-definitions/policy-definition` (key `name`) | `:664` | `holo-policy/src/northbound/configuration.rs:70`, `:394` |
| `…/policy-definition/name` | `:671` | key |
| `…/policy-definition/statements` | `:677` | — |
| `…/statements/statement` (key `name`) | `:680` | `holo-policy/src/northbound/configuration.rs:408`, `:422` |
| `…/statement/name` | `:687` | key |
| `…/statement/conditions` | `:692` | — |
| `…/conditions/match-prefix-set` | `:735` | — |
| `…/match-prefix-set/prefix-set` (leafref, `require-instance`) | `:736` | `holo-policy/src/northbound/configuration.rs:456` |
| `…/statement/actions` | `:794` | — |
| `…/actions/policy-result` (`accept-route`) | `:798`, typedef `policy-result-type` at `:322` | `holo-policy/src/northbound/configuration.rs:503` |
| `…/actions/ietf-bgp-policy:bgp-actions` | augment `ietf/ietf-bgp-policy@2023-07-05.yang:624`, container at `:629` | module in `implemented_modules::POLICY`, `holo-yang/src/lib.rs:320` |
| `…/bgp-actions/set-next-hop` (`self`) | `ietf-bgp-policy@2023-07-05.yang:642`, typedef `bgp-next-hop-type:101`, `enum self:105` | `holo-policy/src/northbound/configuration.rs:1022` |
| `…/bgp-actions/set-med` (`igp`) | `ietf-bgp-policy@2023-07-05.yang:647`, typedef `bgp-set-med-type:116`, `enum igp:125` | `holo-policy/src/northbound/configuration.rs:1026`; `BgpSetMed::Igp` parsed at `holo-utils/src/policy.rs:655`; **implemented on this branch** at `holo-bgp/src/policy.rs:472-478` (fork commit `265610ae`) — before it, the arm was `// TODO` and did nothing |

Deviations file for this module: `deviations/holo-ietf-routing-policy-deviations.yang`. Its only
`not-supported` is `/routing-policy/policy-definitions/match-modified-attributes` (`:37`), which no
leaf above touches. Its two `deviate add default "any"` (`:21`, `:27`) set `match-set-options`, so
that leaf is correctly omitted from the fixture.

### The BGP instance (`bgp-instance`)

| yang path | proof it exists | proof it is supported (holo binding) |
|---|---|---|
| `control-plane-protocol/type` = `ietf-bgp:bgp` | identity string at `holo-utils/src/protocol.rs:98` | — |
| `control-plane-protocol/name` = `cfab` | `ietf/ietf-routing@2018-03-13.yang` list key | — |
| `…/ietf-bgp:bgp` | `ietf/ietf-bgp@2023-07-05.yang:271` | module in `implemented_modules::BGP`, `holo-yang/src/lib.rs:256` |
| `…/bgp/global` (presence) | `ietf-bgp@2023-07-05.yang:274` | `holo-bgp/src/northbound/configuration.rs:252` |
| `…/global/as` = `65000` (mandatory) | `:278` | `holo-bgp/src/northbound/configuration.rs:255` |
| `…/global/identifier` = `10.249.0.1` (dotted-quad) | `:285` | `holo-bgp/src/northbound/configuration.rs:259` |
| `…/global/afi-safis` | `:352` | — |
| `…/afi-safis/afi-safi` (key `name`) | `:356` | `holo-bgp/src/northbound/configuration.rs:296`, `:413`ff |
| `…/afi-safi/name` = `iana-bgp-types:ipv4-unicast` | grouping `mp-afi-safi-config`, `ietf/ietf-bgp-common-multiprotocol@2023-07-05.yang:138` | identity string at `holo-utils/src/bgp.rs:85` |
| `…/afi-safi/apply-policy` | grouping `apply-policy-group` used at `ietf-bgp-common-multiprotocol@2023-07-05.yang:159`; container at `ietf-routing-policy@2021-10-11.yang:500` | `holo-bgp/src/northbound/configuration.rs:443` |
| `…/apply-policy/import-policy` (leafref, ordered-by user) | `ietf-routing-policy@2021-10-11.yang:506` | `holo-bgp/src/northbound/configuration.rs:443`; consumed at `holo-bgp/src/ibus/rx.rs:142` |
| `…/afi-safi/ipv4-unicast` (`when ../name = 'bt:ipv4-unicast'`) | `ietf-bgp-common-multiprotocol@2023-07-05.yang:160` | — |
| `…/ipv4-unicast/holo-bgp:redistribution` (key `type`) | `augmentations/holo-bgp.yang:185` (augment), `:188` (list), `:193` (leaf `type`) | `holo-bgp/src/northbound/configuration.rs:480` → `:493` |
| `…/redistribution/type` = `ietf-routing:direct` | identityref to `rt:control-plane-protocol` | `holo-utils/src/protocol.rs:99` / `:118` |
| `…/redistribution/type` = `ietf-ospf:ospfv2` | same | `holo-utils/src/protocol.rs:103` / `:122` |
| `…/ipv4-unicast/holo-bgp:network` (leaf-list, `inet:ip-prefix`) = `10.249.0.1/32` | same augment, `augmentations/holo-bgp.yang:208` — locally-originated prefixes advertised with origin IGP and MED 0, independent of redistribution; fixes the owner's own identity /32 never being redistributed (holo flags a non-loopback /32 UNNUMBERED, so there is no connected DIRECT route for it) | `InstanceAfiSafiCfg.network: BTreeSet<IpNetwork>` (`holo-bgp/src/northbound/configuration.rs:92`), callback `apply_afi_safi_network` (`:493`, `:535`) queues `Event::NetworkOriginate`, dispatched at `:903-922` to `events::network_originate`/`network_withdraw` in `holo-bgp/src/events.rs` |
| `…/bgp/neighbors` | `ietf-bgp@2023-07-05.yang:381` | — |
| `…/neighbors/neighbor` (key `remote-address`) | `:385` | `holo-bgp/src/northbound/configuration.rs:327`, `:540`ff |
| `…/neighbor/remote-address` = `192.168.249.254` | `:391` | key |
| `…/neighbor/peer-as` = `65000` | `ietf/ietf-bgp-common@2023-07-05.yang:244`; **deviated `mandatory true`** by `deviations/holo-ietf-bgp-deviations.yang:41` | `holo-bgp/src/northbound/configuration.rs:544` |
| `…/neighbor/timers` | `ietf-bgp-common@2023-07-05.yang:356` | — |
| `…/timers/connect-retry-interval` = `3` (range `1..max`, default 120) | `ietf-bgp-common@2023-07-05.yang:106` | `holo-bgp/src/northbound/configuration.rs:560` |
| `…/timers/hold-time` = `3` (range `0 \| 3..65535`, default 90) | `ietf-bgp-common@2023-07-05.yang:119` | `holo-bgp/src/northbound/configuration.rs:563` |
| `…/timers/keepalive` = `1` (range `0..21845`) | `ietf-bgp-common@2023-07-05.yang:155` | `holo-bgp/src/northbound/configuration.rs:566` |
| `…/neighbor/transport` | `ietf-bgp-common@2023-07-05.yang:362` | — |
| `…/transport/local-address` = `192.168.249.1` | `ietf-bgp-common@2023-07-05.yang:408` (union ip-address \| interface-ref) | `holo-bgp/src/northbound/configuration.rs:575`; leaf type pinned to `IpAddr` in `holo-bgp/build.rs` |
| `…/neighbor/afi-safis` | `ietf-bgp@2023-07-05.yang:571`, grouping `bgp-neighbor-afi-safi-list` at `ietf/ietf-bgp-neighbor@2023-07-05.yang:69` | — |
| `…/afi-safis/afi-safi` (key `name`) | `ietf-bgp-neighbor@2023-07-05.yang:72` | `holo-bgp/src/northbound/configuration.rs:665`, `:689`ff |
| `…/afi-safi/enabled` = `true` (default false) | `ietf-bgp-common-multiprotocol@2023-07-05.yang:145` | `holo-bgp/src/northbound/configuration.rs:689`; **load-bearing**: the IPv4-unicast MP capability is only sent when it is true — `holo-bgp/src/neighbor.rs:757-758` |
| `…/afi-safi/apply-policy/export-policy` | `ietf-routing-policy@2021-10-11.yang:527` | `holo-bgp/src/northbound/configuration.rs:703` |

Deviations file for this module: `deviations/holo-ietf-bgp-deviations.yang`. Nothing above appears
in its `not-supported` block (`:57`-`:279`); the closest neighbors of our paths that *are* removed
are `global/route-selection-options/med-plus-igp` (`:69`), the global-afi-safi twin (`:81`),
`neighbors/neighbor/peer-group` (`:157`), and every non-`ipv[46]-unicast` afi-safi (`:93`-`:123`,
`:201`-`:231`). Note the asymmetry that cost us a wrong guess earlier: the **`med-plus-igp` route
selection option is `not-supported`**, but the **`set-med med-plus-igp` policy action is a different
node in a different module** and is supported.

## 5. Why the fixture is shaped the way it is (the requirements)

- **R1** — one instance, `identifier` = the first gw zone's identity address. `identifier` is the
  BGP router-id; `/routing/router-id` is deviated `not-supported`
  (`deviations/holo-ietf-routing-deviations.yang:42`), so per-instance is the only place it can go.
- **R2** — one neighbor per gw row, iBGP (`peer-as` == `global/as`), fast timers, and **`passive-mode`
  is absent**. Its default is `false` (`ietf-bgp-common@2023-07-05.yang:461`), and this fork *refuses
  the commit* if it is set to `true` while the instance runs under `BgpListenPolicy::NoListener`
  (`holo-bgp/src/northbound/configuration.rs:241`, message at `:244`, test at `:1232`). Emitting an
  explicit `false` would be a second spelling of the default with no benefit.
- **R3 + R4** — redistribution of `direct` and `ospfv2` hangs off the **global** afi-safi entry's
  `ipv4-unicast` container (holo's own augment), not off the neighbor.
- **R5** — the neighbor's afi-safi carries an **explicit** export policy. `default-export-policy`
  defaults to `reject-route` (`ietf-routing-policy@2021-10-11.yang:541`), so a missing attachment
  advertises nothing while the session sits Established. The policy matches `cfab-mgmt-id`, sets
  `set-next-hop self`, and ends in `accept-route`.
- **R6** — `cfab-mgmt-id` is `10.249.0.0/24` with both mask-length bounds pinned to 32, i.e. exactly
  the identity /32s. Matching is `range.prefix.contains(prefix.ip()) && len >= lower && len <= upper`
  (`holo-utils/src/policy.rs:161-167`), so: identity `10.249.0.1/32` matches (contained, len 32); the
  identity block `10.249.0.0/24` itself does **not** (len 24 < 32); and a segment /24 such as
  `10.249.1.0/24` does not (not contained). One set serves both the import and the export policy —
  the same `ge 32` shape that keeps segment /24s out of the router.
- **Global import (parent §3.4a)** — `cfab-mgmt-import` is attached at
  `global/afi-safis/afi-safi[ipv4-unicast]/apply-policy/import-policy`. Redistributed routes run the
  **global afi-safi** apply-policy, which *shadows* (never merges with) the instance-level one:
  `holo-bgp/src/ibus/rx.rs:122-127` is `…afi_safi.apply_policy).unwrap_or(&instance.config.apply_policy)`.
  Without an explicit import policy the default is `reject-route`
  (`ietf-routing-policy@2021-10-11.yang:520`) and every redistributed route is dropped with no error.
  The policy sets `set-med igp`, which this fork wires to the IGP metric carried from the
  redistribution message (`holo-bgp/src/ibus/rx.rs:138` → `holo-bgp/src/policy.rs:472-478`).
- **R7 — an absence, deliberately.** There is **no** neighbor-level deny-all *import* policy in the
  fixture and there must not be one. The neighbor afi-safi's `apply-policy` carries only
  `export-policy`; `default-import-policy` is left unset and therefore `reject-route`
  (`ietf-routing-policy@2021-10-11.yang:520`), which is already the behavior a deny-all policy would
  buy. Emitting one would be a second spelling of the same rule and one more name to keep in sync.
- **INVARIANT — no dangling policy name.** Every name in an `import-policy` / `export-policy`
  leaf-list is defined in the same document. holo does `shared.policies.get(policy).unwrap()`
  (`holo-bgp/src/ibus/rx.rs:144`) and would panic. Verified that libyang catches this first: the
  leafref has `require-instance true` (`ietf-routing-policy@2021-10-11.yang:506`) and a bogus name is
  rejected — see §6.
- **INVARIANT — apply-policy shadows, it does not merge.** The global afi-safi entry and the neighbor
  afi-safi entry therefore each carry their own `apply-policy`, one import and one export
  respectively. (`holo-bgp/src/ibus/rx.rs:122-127` for import;
  `holo-bgp/src/events.rs:327-332` for the neighbor side.)

## 6. What was verified by running (E1.1 throwaway harness, not committed)

A scratch `#[cfg(test)]` block merged this fixture into `emit::engine::generate(pve1-tb)` and handed
the result to libyang through a context built exactly as `src/engine/northbound.rs:36-39` builds it,
plus `BGP` and `POLICY`:

- **Accepted** with `DataValidationFlags::NO_STATE`, and **accepted again under
  `DataParserFlags::STRICT`** — the strong result: under STRICT, libyang errors on any node absent
  from the *deviated* schema, so every leaf in the fixture is proven present and not
  `not-supported`. All values survived the round-trip reprint.
- **Negative control (deviation bites):** injecting `global/route-selection-options/med-plus-igp`
  (deviated `not-supported`) is rejected under STRICT with `Node "med-plus-igp" not found as a child
  of "route-selection-options" node.`
- **Negative control (leafref bites):** an `import-policy` naming an undefined policy is rejected
  even in non-strict mode: `Invalid leafref value "cfab-does-not-exist" - no target instance …`.

## 7. Two findings E1.2/E1.3 must act on

1. **`src/engine/northbound.rs:37` loads `[INTERFACE, ROUTING, OSPF, BFD]`.** `BGP` and `POLICY` are
   separate lists (`holo-yang/src/lib.rs:256` and `:317`) and are **not** currently loaded, so this
   fixture cannot be committed to the engine until E1.3 adds both. `ietf-routing-policy` and
   `ietf-bgp-policy` live only in `POLICY`; adding `BGP` alone is not enough.
2. **A `not-supported` node is silently dropped, not rejected.** `parse_candidate`
   (`src/engine/northbound.rs:47-57`) parses with `DataParserFlags::empty()`. Measured above: the
   deviated `med-plus-igp` leaf parsed **successfully** and simply vanished from the reprint. The
   brief assumed libyang would reject such a path; it does not — cfab would ship a config the engine
   never sees, with no error anywhere. Switching `parse_candidate` to `DataParserFlags::STRICT` turns
   that into a loud failure. Recorded here, not changed: it is outside E1.1's scope and touches every
   existing emitter.
