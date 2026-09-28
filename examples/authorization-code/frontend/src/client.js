import { shallowRef } from "vue";
import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
} from "oidc-client-ts";

export const authority =
  import.meta.env.VITE_AUTHORITY || "http://localhost:8080";
export const clientId = "authorization-code-public-client";
export const user = shallowRef(null);
export const manager = new UserManager({
  authority,
  client_id: clientId,
  redirect_uri: `${window.location.origin}/callback`,
  post_logout_redirect_uri: `${window.location.origin}/`,
  response_type: "code",
  scope: "openid profile message.read",
  automaticSilentRenew: false,
  loadUserInfo: true,
  staleStateAgeInSeconds: 300,
  // Only the short-lived authorization transaction survives redirects. Tokens stay in memory.
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
});
