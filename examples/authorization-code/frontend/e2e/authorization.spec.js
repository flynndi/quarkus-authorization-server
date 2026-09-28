import { test, expect } from "@playwright/test";

test("server login and consent, Vue PKCE callback, bearer API and OIDC logout", async ({
  page,
  context,
  browser,
}, testInfo) => {
  // Start with partial consent from a separate browser that has JavaScript disabled.
  await verifyDefaultPagesWithoutJavaScript(browser, testInfo);
  await page.goto("/");
  await page.getByRole("button", { name: "开始授权" }).click();
  await expect(page).toHaveURL("http://localhost:18080/auth/login");
  const savedRequest = (await context.cookies()).find(
    (cookie) => cookie.name === "quarkus-redirect-location",
  )?.value;
  expect(savedRequest).toContain("/oauth2/authorize?");
  await page.getByLabel("Username", { exact: true }).fill("resource-owner");
  await page.getByLabel("Password", { exact: true }).fill("wrong-password");
  const [failure] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.url() === "http://localhost:18080/j_security_check",
    ),
    page.getByRole("button", { name: "Sign in" }).click(),
  ]);
  expect(failure.status()).toBe(302);
  expect(failure.request().isNavigationRequest()).toBe(true);
  const formHeaders = await failure.request().allHeaders();
  expect(formHeaders.origin).toBe("http://localhost:18080");
  expect(formHeaders.referer).toBe("http://localhost:18080/");
  await expect(page).toHaveURL("http://localhost:18080/auth/login?error=true");
  await expect(page.getByRole("alert")).toContainText("Invalid username or password");
  expect(
    (await context.cookies()).find(
      (cookie) => cookie.name === "quarkus-redirect-location",
    )?.value,
  ).toBe(savedRequest);
  await page.getByLabel("Username", { exact: true }).fill("resource-owner");
  await page
    .getByLabel("Password", { exact: true })
    .fill("resource-owner-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/^http:\/\/localhost:18080\/oauth2\/authorize\?/);
  await expect(page.getByRole("heading", { name: "Consent required" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeEnabled();
  await page.getByRole("button", { name: "Deny", exact: true }).click();
  await expect(page).toHaveURL(/\/result$/);
  await expect(page.getByRole("alert")).toContainText("access_denied");
  await page.getByRole("link", { name: "返回客户端首页" }).click();
  await page.getByRole("button", { name: "开始授权" }).click();
  await expect(page).toHaveURL(/^http:\/\/localhost:18080\/oauth2\/authorize\?/);
  await expect(page.getByRole("heading", { name: "Consent required" })).toBeVisible();
  await approveConsent(page);
  await expect(page).toHaveURL(/\/result$/);
  await expect(
    page.getByRole("heading", { name: "授权完成", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "调用受保护 API" }).click();
  await expect(page.locator(".resource-result")).toContainText(
    "Hello from the protected Quarkus API",
  );
  const cookies = await context.cookies("http://localhost:18080");
  expect(
    cookies.find((cookie) => cookie.name === "quarkus-credential")?.httpOnly,
  ).toBe(true);
  expect(
    cookies.find((cookie) => cookie.name === "quarkus-credential.oidc")
      ?.httpOnly,
  ).toBe(true);
  expect(
    cookies.some((cookie) => cookie.name === "quarkus-redirect-location"),
  ).toBe(false);
  const storage = await page.evaluate(() => ({
    local: { ...localStorage },
    session: { ...sessionStorage },
  }));
  expect(JSON.stringify(storage)).not.toContain("access_token");
  const [logout] = await Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === "/connect/logout"),
    page.getByRole("button", { name: "退出登录并清除页面令牌" }).click(),
  ]);
  expect(logout.status()).toBe(302);
  expect(logout.request().isNavigationRequest()).toBe(true);
  expect(new URL(logout.url()).searchParams.has("id_token_hint")).toBe(true);
  await expect(page).toHaveURL("http://localhost:5173/");
  expect(
    (await context.cookies()).some((cookie) =>
      cookie.name.startsWith("quarkus-credential"),
    ),
  ).toBe(false);
});

test("scope restriction is enforced by the resource server", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("checkbox", { name: /message.read/ }).uncheck();
  await page.getByRole("button", { name: "开始授权" }).click();
  await fillCredentials(page);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/(oauth2\/authorize|callback|result)/);
  if (new URL(page.url()).pathname === "/oauth2/authorize")
    await approveConsent(page);
  await expect(page).toHaveURL(/\/result$/);
  await page.getByRole("button", { name: "调用受保护 API" }).click();
  await expect(page.getByRole("alert")).toContainText("HTTP 403");
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "尚未获得访问令牌" }),
  ).toBeVisible();
});

test("unknown callback state fails and is removed from the address bar", async ({
  page,
}) => {
  await page.goto("/callback?code=untrusted-code&state=untrusted-state");
  await expect(page).toHaveURL(/\/result$/);
  await expect(page.getByRole("alert")).toContainText("state");
  await expect(
    page.getByRole("button", { name: "调用受保护 API" }),
  ).toHaveCount(0);
});

test("mobile server login needs no home or session endpoint", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("http://localhost:18080/auth/login?returnTo=https://untrusted.example");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await fillCredentials(page);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL("http://localhost:18080/auth/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.goto("/");
  await page.getByRole("button", { name: "开始授权" }).click();
  await expect(page).toHaveURL(/\/(oauth2\/authorize|result)/);
});

async function verifyDefaultPagesWithoutJavaScript(browser, testInfo) {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    const authorize = new URL("http://localhost:18080/oauth2/authorize");
    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: "authorization-code-public-client",
      redirect_uri: "http://localhost:5173/callback",
      scope: "openid profile",
      state: "no-javascript-approve",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
    }).toString();
    await page.goto(authorize.toString());
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("default-login.png") });
    await fillCredentials(page);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Consent required" })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: testInfo.outputPath("default-consent-mobile.png") });
    await approveConsent(page);
    await expect(page).toHaveURL(/\/callback\?code=/);
    expect(new URL(page.url()).searchParams.get("state")).toBe("no-javascript-approve");
    expect(new URL(page.url()).searchParams.get("code")).toBeTruthy();

    authorize.searchParams.set("state", "no-javascript-deny");
    authorize.searchParams.set("scope", "openid profile message.read");
    await page.goto(authorize.toString());
    await expect(page.getByRole("heading", { name: "Consent required" })).toBeVisible();
    await page.getByRole("button", { name: "Deny" }).click();
    await expect(page).toHaveURL(/\/callback\?error=access_denied/);
    expect(new URL(page.url()).searchParams.get("state")).toBe("no-javascript-deny");
  } finally {
    await context.close();
  }
}

async function fillCredentials(page) {
  await page.getByLabel("Username", { exact: true }).fill("resource-owner");
  await page.getByLabel("Password", { exact: true }).fill("resource-owner-password");
}

async function approveConsent(page) {
  for (const scope of await page.locator('input[name="scope"]:enabled').all())
    await scope.check();
  await page.getByRole("button", { name: "Approve" }).click();
}
