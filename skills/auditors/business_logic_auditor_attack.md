> **Skill ID**: S-055-B | **Phase**: 4 | **Stage**: 2 (Attack)
> **Input**: attack_plans/{sink_id}_plan.json, Docker container access
> **Output**: exploit_results/{sink_id}_result.json, PoC脚本/{sink_id}_poc.py

## 8 Rounds of Attack

### R1 - Price and Quantity Tampering

Objective: Modify prices or quantities in orders to gain illegitimate benefits.

Attack steps:
1. **Client-side price tampering**:
   ```bash
   # Modify the hidden price field
   docker exec php curl -s -X POST http://nginx:80/api/order \
     -H "Cookie: $SESSION" \
     -d '{"item_id":1,"quantity":1,"price":0.01}'
   ```
2. **Quantity tampering**:
   - Quantity set to 0: `quantity=0` → Free order?
   - Quantity set to negative: `quantity=-1` → Refund?
   - Quantity set to decimal: `quantity=0.001` → Rounding discrepancy?
   - Quantity set to extreme value: `quantity=99999999` → Integer overflow?
3. **Currency tampering**: `currency=VND` → Use low exchange rate currency
4. **Where is the price sourced from?**:
   - Submitted from frontend → Extremely high risk
   - Database query without validation → High risk
   - Fixed on backend → Safe

**Success Criteria:** Complete an order at below-normal price.

### R2 - Coupon/Discount Abuse

Attack steps:
1. **Reuse the same coupon multiple times**:
   - Concurrent requests (defer to race condition auditor)
   - Apply repeatedly across different orders
2. **Discount stacking**:
   - Coupon + membership discount + threshold-based reduction all applied simultaneously
   - Multiple coupons stacked
3. **Coupon tampering**:
   - Modify discount amount: `discount_amount=99999`
   - Modify discount type: `discount_type=fixed` → `discount_type=percent`
4. **Expired coupons**: Modify client-side time or time parameter in requests
5. **Coupon enumeration**: `code=SAVE10`, `code=SAVE20`, `code=SAVE50` — Predictable patterns
6. **Negative discount**: `discount=-100` → Price increase (may become revenue in refund scenarios)

**Success Criteria:** Obtain discounts beyond intended limits or free merchandise.

### R3 - Payment Flow Bypass

Attack steps:
1. **Skip payment step**:
   ```bash
   # Directly call the payment confirmation endpoint
   docker exec php curl -s -X POST http://nginx:80/api/order/confirm \
     -H "Cookie: $SESSION" \
     -d '{"order_id":123}'
   ```
2. **Modify payment callback**:
   - Forge payment gateway callback notification
   - Modify amount: Pay 0.01 but order amount is 100
   - Modify status: `status=success` to directly mark as paid
3. **Payment status confusion**:
   - Order unpaid but directly request shipment endpoint
   - Modify order status field to bypass payment check
4. **Refund abuse**:
   - Pay then request refund, but goods/services already consumed
   - Duplicate refund: Multiple refund requests for the same order
   - Partial refund amount tampering: `refund_amount=200` (order amount 100)

**Success Criteria:** Obtain goods/services without paying or underpaying.

### R4 - Multi-Step Flow Step-Skipping

Attack steps:
1. **Registration flow**:
   - Skip email verification and log in directly
   - Skip phone verification and use features directly
   - Skip identity verification and trade directly
2. **Approval flow**:
   - Directly call the final execution endpoint, bypassing approval steps
   - Self-approve: Submitter is also the approver
3. **KYC flow**:
   - Skip identity verification and withdraw directly
   - Use another person's KYC materials
4. **Purchase flow**:
   - Skip address input and place order directly
   - Skip inventory check and proceed to payment directly

Implementation methods:
- Directly request API endpoints for subsequent steps
- Modify flow state markers in Session/Cookie
- Remove hidden fields for frontend step checks

**Success Criteria:** Critical business steps are bypassed.

### R5 - Negative and Boundary Value Attacks

Attack steps:
1. **Negative value attacks**:
   - Negative transfer amount: `amount=-100` → Deduct from recipient's account?
   - Negative purchase quantity: `qty=-1` → Generate refund?
   - Negative points consumption: `points=-500` → Points increase?
2. **Zero value attacks**:
   - Amount of 0 → Free order
   - Fee rate of 0 → No service fee
3. **Extreme values**:
   - Integer maximum: `2147483647` → Overflow
   - Floating-point precision: `0.1 + 0.2 != 0.3` → Calculation discrepancy
   - Scientific notation: `1e10` → Parsing discrepancy
4. **Data type confusion**:
   - String "100" vs number 100
   - Array `amount[]=100` replacing scalar
   - null/undefined values

**Success Criteria:** Achieve financial anomaly or business rule bypass through boundary values.

### R6 - Email/SMS Bombing

Attack steps:
1. **Password reset bombing**:
   ```bash
   for i in $(seq 1 50); do
     curl -s -X POST http://nginx:80/api/forgot-password \
       -d "email=victim@example.com" &
   done
   ```
2. **Verification code bombing**: Repeatedly request verification code sends
3. **Notification bombing**: Trigger mass push/email notifications
4. **Invitation bombing**: Repeatedly send invitation emails

Analysis:
- Whether rate limiting exists
- Whether daily caps exist
- Whether CAPTCHA protection exists
- Whether limits are IP-based or account-based

**Success Criteria:** Successfully send more than a reasonable number of emails/SMS to the target.

### R7 - State Machine Anomalies

Objective: Exploit illegal state transitions in the state machine.

Analysis:
```
Normal flow: pending → paid → shipped → completed
                                    → refunded
```

Attacks:
1. **Reverse transition**: `completed → pending` → Reuse?
2. **Jump transition**: `pending → completed` → Bypass payment?
3. **Cancelled order operations**: `cancelled → shipped` → Ship anyway?
4. **Parallel states**: Simultaneously trigger `shipped` and `refunded`

Code audit:
```bash
# Search for state transition logic
grep -rn "status.*=\|setState\|updateStatus\|transition" \
  $TARGET_PATH/ --include="*.php"
```

Analyze whether each state transition validates the preceding state.

**Success Criteria:** Achieve an illegal state transition.

### R8 - Combined Business Logic Chains

1. **Coupon enumeration → Stacking → Negative payment → Refund to account**: Enumerate coupon codes → Stack discounts exceeding order amount → System refunds the difference → Net profit
2. **Registration reward abuse → Mass registration → Reward withdrawal**: Each new user receives a reward → Mass register → Transfer rewards to main account → Withdraw
3. **Price tampering → Low-price order → Normal refund**: Place order at 0.01 → Use the service → Request full refund
4. **Flow step-skipping → KYC bypass → Unverified transactions**: Skip identity verification → Use others' funds → Anonymous transactions
5. **Points system abuse**: Redeem points for goods → Return for cash refund but points not deducted back

**Success Criteria:** A complete business logic exploitation chain resulting in actual financial loss.

## Evidence Requirements

| Evidence Type | Example |
|---|---|
| Price tampering | Order amount 0.01 but received goods worth 100 |
| Flow bypass | Unpaid order status changed to completed |
| Coupon abuse | Same coupon successfully used across 5 orders |
| Negative value attack | Sender's balance increased by 100 after transferring -100 |
| SMS bombing | 30 verification codes successfully sent within 60 seconds |
| State anomaly | Cancelled order successfully shipped |

## Report Format

```json
{
  "vuln_type": "BusinessLogic",
  "sub_type": "price_tamper|coupon_abuse|payment_bypass|flow_skip|negative_value|sms_bomb|state_machine",
  "round": 1,
  "endpoint": "POST /api/order",
  "payload": "{\"item_id\":1,\"quantity\":1,\"price\":0.01}",
  "expected_behavior": "Price SHOULD be read from the database and NOT accepted from client input",
  "actual_behavior": "Order successfully created at 0.01",
  "evidence": "Order #123 amount 0.01, original product price 99.99",
  "confidence": "confirmed|highly_suspected|potential_risk",
  "impact": "Financial loss|business rule bypass|abuse attack",
  "remediation": "Validate all business rules server-side, read prices from database, use database transactions to ensure atomicity, strictly validate preconditions for state transitions"
}
```

## Detection (Vulnerability Pattern Recognition)

The following code patterns indicate possible business logic flaws:
- Pattern 1: `$price = $_POST['price']; $total = $price * $qty;` — Price submitted by client, can be tampered to negative or extremely small values
- Pattern 2: `if($step == 3) { processPayment(); }` without preceding step validation — Multi-step flows can skip intermediate verification steps
- Pattern 3: `$discount = Coupon::where('code', $code)->first(); $order->apply($discount);` without usage check — Coupons/redemption codes can be reused
- Pattern 4: `User::where('email', $input)->first()->sendResetLink()` without rate limiting — Password reset/SMS verification has no frequency control, enabling bombing
- Pattern 5: `if($balance >= $amount) { transfer($from, $to, $amount); }` — Balance/inventory check and deduction are not atomic operations (cross-reference with race conditions)
- Pattern 6: `$qty = abs(intval($_POST['qty']))` but without upper limit — Quantity/amount boundary values not validated (0, negative, extremely large, decimals)

## Key Insight

> **Key Point**: Business logic vulnerabilities cannot be detected through automated Sink detection; they require understanding the business flow before conducting semantic-level attack verification. The core audit principle is "whether each business assumption is enforced server-side" — prices MUST NOT be tampered, flows MUST NOT be skipped, resources MUST NOT be over-consumed, operations MUST NOT be infinitely repeatable. Focus on operations involving money/points/inventory/permission changes, and state machine integrity of multi-step flows.

### Smart Pivot (Stuck Detection)

When 3 consecutive rounds fail (current round ≥ 4), trigger Smart Pivot:

1. Re-reconnaissance: Re-read target code to find missed filtering logic and alternative entry points
2. Cross-intelligence: Consult the shared findings store (`$WORK_DIR/audit_session.db`) for related findings from other experts
3. Decision tree matching: Select new attack direction based on failure patterns in `shared/pivot_strategy.md`
4. When no new paths exist, terminate early to avoid wasting rounds and producing hallucinated results

## Prerequisites and Scoring (MUST be completed)

The output `exploits/{sink_id}.json` MUST include the following two objects:

### prerequisite_conditions
```json
{
  "auth_requirement": "anonymous|authenticated|admin|internal_network",
  "bypass_method": "Authentication bypass method, null if none",
  "other_preconditions": ["Precondition 1", "Precondition 2"],
  "exploitability_judgment": "directly_exploitable|conditionally_exploitable|not_exploitable"
}
```
- `auth_requirement` MUST match the auth_level for that route in auth_matrix.json
- `exploitability_judgment = "not_exploitable"` → final_verdict SHALL be at most potential
- `other_preconditions` SHALL list all non-authentication prerequisites (e.g., PHP configuration, Composer dependencies, environment variables)

### severity (Three-dimensional scoring, see shared/severity_rating.md for details)
```json
{
  "reachability": 0-3, "reachability_reason": "...",
  "impact": 0-3, "impact_reason": "...",
  "complexity": 0-3, "complexity_reason": "...",
  "score": "R×0.40+I×0.35+C×0.25",
  "cvss": "(score/3.0)×10.0",
  "level": "C|H|M|L",
  "vuln_id": "C-RCE-001"
}
```
- All reason fields MUST contain specific justification and MUST NOT be empty
- score and evidence_score MUST be consistent (≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3)

### Evidence Contract Reference (EVID)

Each vulnerability conclusion MUST reference the following evidence points in the `evidence` field (refer to `shared/evidence_contract.md`):
- `EVID_BIZ_FLOW_DESCRIPTION` — Business flow description ✅ Required
- `EVID_BIZ_BYPASS_POINT` — Bypass point ✅ Required
- `EVID_BIZ_STATE_PERSISTENCE` — State persistence ✅ Required
- `EVID_BIZ_EXPLOIT_RESPONSE` — Exploitation response evidence (required when confirmed)

Missing required EVIDs → conclusion is automatically downgraded (confirmed→suspected→unverified).

### Attack Memory Write

After the attack cycle ends, write experiences to the attack memory store (see `shared/attack_memory.md` write protocol for format):

- ✅ confirmed: Record successful payload type + bypass technique + successful round
- ❌ failed (≥3 rounds): Record all excluded strategies + failure reasons
- ⚠️ partial: Record partially successful strategies + blocking reasons
- ❌ failed (<3 rounds): Do not record

Use `bash tools/audit_db.sh memory-write '<json>'` to write. SQLite WAL mode automatically ensures concurrency safety.

## Output

After completing all rounds, write the final results to `$WORK_DIR/exploits/{sink_id}.json`, following the format in `shared/data_contracts.md` Section 9 (`exploit_result.json`).

## Collaboration

- Pass concurrency-related findings to the race condition auditor for in-depth testing
- Pass payment bypass findings to the privilege escalation auditor (permission dimension analysis)
- Pass email bombing findings to the configuration auditor (rate limiting configuration analysis)
- Submit all findings to the QA reviewer for evidence verification

## Constraints

- Completing actual real payments or transfers is PROHIBITED
- Test orders MUST use test data and MUST NOT affect production data
- SMS/email bombing tests are limited to a maximum of 50 attempts; stop once a repeatable pattern is confirmed through observation
- Create Docker snapshots before each attack round and roll back after
- Business logic testing requires extracting business context; blind brute-force testing is PROHIBITED


---

## Pre-Submission Self-Check (MUST be performed)

After completing the exploit JSON, perform item-by-item self-check per `shared/auditor_self_check.md`:

1. Execute the 8 general items (G1-G8); proceed only after all are ✅
2. Execute the specialized self-check items below (S1-S3); submit only after all are ✅
3. If any item is ❌ → correct and re-check; skipping is NOT permitted

### Specialized Self-Check (Business Logic Auditor Specific)
- [ ] S1: Complete attack flow for business logic flaws (preconditions → operation steps → anomalous results) has been annotated
- [ ] S2: Comparison between normal business flow and attack flow has been demonstrated
- [ ] S3: Business impact (financial loss/data tampering/permission bypass) has been quantitatively assessed

## Shared Protocols
> 📄 `skills/shared/round_record_format.md` (S-101) — Per-round JSON format
> 📄 `skills/shared/smart_skip_protocol.md` (S-102) — Smart skip
> 📄 `skills/shared/smart_pivot_protocol.md` (S-103) — Smart pivot
> 📄 `skills/shared/prerequisite_scoring_3d.md` (S-104) — 3D scoring
> 📄 `skills/shared/attack_memory_writer.md` (S-105) — Memory write
> 📄 `skills/shared/second_order_tracking.md` (S-106) — Second-order tracking
> 📄 `skills/shared/general_self_check.md` (S-108) — G1-G8 self-check
