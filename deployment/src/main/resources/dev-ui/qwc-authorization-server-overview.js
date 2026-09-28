import { LitElement, html, css } from 'lit';
import { overview } from 'build-time-data';
import { JsonRpc } from 'jsonrpc';

export class QwcAuthorizationServerOverview extends LitElement {
    static properties = {
        _runtime: { state: true },
        _tenantIds: { state: true },
        _selectedTenant: { state: true },
        _loading: { state: true },
        _error: { state: true }
    };

    jsonRpc = new JsonRpc(this);

    constructor() {
        super();
        this._runtime = null;
        this._tenantIds = [];
        this._selectedTenant = '';
        this._loading = false;
        this._error = false;
        this._request = 0;
    }

    static styles = css`
        :host {
            display: block;
            padding: var(--lumo-space-l);
            color: var(--lumo-body-text-color);
        }
        h2, h3 { margin: 0 0 var(--lumo-space-s); }
        p { line-height: 1.6; }
        .description, .note { color: var(--lumo-secondary-text-color); }
        .summary, .features { display: flex; flex-wrap: wrap; gap: var(--lumo-space-m); }
        .summary { margin: var(--lumo-space-l) 0; }
        .summary > div {
            min-width: 12rem;
            padding: var(--lumo-space-m);
            border: 1px solid var(--lumo-contrast-20pct);
            border-radius: var(--lumo-border-radius-m);
        }
        dt { color: var(--lumo-secondary-text-color); margin-bottom: var(--lumo-space-s); }
        dd { margin: 0; font-weight: 600; }
        .feature { padding: var(--lumo-space-xs) var(--lumo-space-s); background: var(--lumo-contrast-5pct); }
        .enabled { color: var(--lumo-success-text-color); }
        .disabled { color: var(--lumo-secondary-text-color); }
        .table-scroll { overflow-x: auto; margin-top: var(--lumo-space-l); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        caption { text-align: left; font-size: var(--lumo-font-size-l); font-weight: 600; padding-bottom: var(--lumo-space-m); }
        th, td { padding: var(--lumo-space-m); border-bottom: 1px solid var(--lumo-contrast-10pct); vertical-align: top; }
        th { color: var(--lumo-secondary-text-color); font-size: var(--lumo-font-size-s); }
        code { overflow-wrap: anywhere; font-size: var(--lumo-font-size-s); }
        .method { white-space: nowrap; }
        .note { font-size: var(--lumo-font-size-s); margin-top: var(--lumo-space-xs); }
        a { color: var(--lumo-primary-text-color); }
        a:focus-visible, button:focus-visible, select:focus-visible { outline: 2px solid var(--lumo-primary-color); outline-offset: 3px; }
        .runtime { margin-top: var(--lumo-space-l); padding: var(--lumo-space-m); background: var(--lumo-contrast-5pct); }
        .controls { display: flex; flex-wrap: wrap; align-items: center; gap: var(--lumo-space-m); }
        button, select { font: inherit; color: var(--lumo-body-text-color); background: var(--lumo-base-color);
            padding: var(--lumo-space-xs) var(--lumo-space-s); border: 1px solid var(--lumo-contrast-20pct);
            border-radius: var(--lumo-border-radius-m); }
        button { cursor: pointer; }
        button:disabled { cursor: wait; opacity: 0.6; }
        .error { color: var(--lumo-error-text-color); }
        .address-label { margin-top: var(--lumo-space-s); color: var(--lumo-secondary-text-color); font-size: var(--lumo-font-size-xs); }
        .assembly { margin-top: var(--lumo-space-l); border: 1px solid var(--lumo-contrast-20pct);
            border-radius: var(--lumo-border-radius-m); padding: var(--lumo-space-m); }
        .details { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: var(--lumo-space-m); }
        .details dd { font-weight: normal; overflow-wrap: anywhere; }
        .provider-origin { display: block; }
    `;

    connectedCallback() {
        super.connectedCallback();
        this._loadRuntime();
    }

    disconnectedCallback() {
        this._request++;
        super.disconnectedCallback();
    }

    async _loadRuntime() {
        const request = ++this._request;
        this._loading = true;
        this._error = false;
        this._runtime = null;
        try {
            const response = await this.jsonRpc.getOverview({ tenantId: this._selectedTenant || null });
            if (request !== this._request) return;
            if (response.error || !response.result) throw new Error('Runtime overview unavailable');
            this._runtime = response.result;
            this._tenantIds = response.result.tenantIds;
        } catch {
            if (request === this._request) this._error = true;
        } finally {
            if (request === this._request) this._loading = false;
        }
    }

    _selectTenant(event) {
        this._selectedTenant = event.target.value;
        this._loadRuntime();
    }

    _localPath(endpoint) {
        if (!overview.multipleIssuers) return endpoint.path;
        if (this._runtime?.status !== 'READY') return null;
        return endpoint.path.replace('{issuer}', this._runtime.tenantId);
    }

    _publishedUrl(endpoint) {
        if (this._runtime?.status !== 'READY') return null;
        const issuer = this._runtime.issuer;
        if (overview.multipleIssuers && endpoint.issuerPath === '/.well-known/oauth-authorization-server') {
            // RFC 8414 places the well-known component before the complete issuer path.
            const url = new URL(issuer);
            return url.origin + endpoint.issuerPath + url.pathname;
        }
        return (issuer.endsWith('/') ? issuer.slice(0, -1) : issuer) + endpoint.issuerPath;
    }

    _runtimeMessage() {
        if (this._loading) return 'Loading runtime issuer information…';
        if (this._error) return 'Runtime information could not be loaded. Refresh to try again.';
        switch (this._runtime?.status) {
            case 'READY': return html`Configured issuer: <code>${this._runtime.issuer}</code>`;
            case 'SELECT_TENANT': return 'Select a tenant to inspect its issuer and endpoint URLs.';
            case 'UNKNOWN_TENANT': return 'The selected tenant is unavailable. Select a configured tenant; no fallback was applied.';
            case 'ISSUER_NOT_CONFIGURED': return html`Issuer is not configured. Set <code>quarkus.authorization-server.issuer</code>
                to publish discovery metadata; the browser origin is not used as an issuer.`;
            default: return 'Runtime information is unavailable.';
        }
    }

    _componentOrigin(component) {
        const kinds = {
            CLASS: 'CDI class bean', PRODUCER_METHOD: 'CDI producer method', PRODUCER_FIELD: 'CDI producer field',
            SYNTHETIC: 'Synthetic CDI bean', TENANT_COMPONENT: 'Component from the selected tenant', UNAVAILABLE: 'Unavailable'
        };
        return [kinds[component.kind] || component.kind, component.scope,
            component.defaultBean ? 'Default CDI bean' : null].filter(Boolean).join(' · ');
    }

    _renderAssembly() {
        const login = this._runtime?.login;
        if (!login) return '';
        const assembly = this._runtime.assembly;
        const signing = assembly?.signing;
        const sources = {
            CONFIGURED_PEM: 'Configured PEM keys', EPHEMERAL: 'Generated ephemeral key',
            APPLICATION_SOURCE: 'Application key source', APPLICATION_MANAGER: 'Application key manager (source is application-owned)',
            TENANT_SOURCE: 'Selected tenant key source'
        };
        const defaultPage = overview.features.find(feature => feature.name === 'Default login page integration')?.enabled;
        return html`
            <section class="assembly" aria-labelledby="login-heading">
                <h3 id="login-heading">Browser login</h3>
                <p>Default login page integration: <strong>${defaultPage ? 'enabled' : 'disabled'}</strong>.
                    Quarkus Form authentication: <strong>${login.formEnabled ? 'enabled' : 'disabled'}</strong>.</p>
                ${login.formEnabled ? html`
                    <dl class="details">
                        <div><dt>Login page</dt><dd><code>${login.loginPage || 'Redirect disabled'}</code></dd></div>
                        <div><dt>Form POST location</dt><dd><code>${login.postLocation}</code></dd></div>
                        <div><dt>Error page</dt><dd><code>${login.errorPage || 'Redirect disabled'}</code></dd></div>
                        <div><dt>Landing page</dt><dd><code>${login.landingPage || 'Redirect disabled'}</code></dd></div>
                        <div><dt>HttpOnly cookie</dt><dd>${login.httpOnlyCookie ? 'Yes' : 'No'}</dd></div>
                        <div><dt>Cookie SameSite</dt><dd>${login.cookieSameSite}</dd></div>
                    </dl>
                    <p class="note">Effective Quarkus Form configuration, including application overrides. These locations start at the server root.
                        ${overview.multipleIssuers ? 'Form configuration is shared by all issuers.' : ''}
                        The application supplies user authentication.</p>` : html`
                    <p class="note">Form login is not installed. The application can supply another browser authentication mechanism.</p>`}
            </section>
            <section class="assembly" aria-labelledby="storage-heading">
                <h3 id="storage-heading">Storage components</h3>
                ${assembly ? html`
                    <div class="table-scroll"><table aria-label="Storage components">
                        <thead><tr><th>Responsibility</th><th>Bean / component class</th><th>Source</th></tr></thead>
                        <tbody>${assembly.storage.map(component => html`<tr>
                            <td>${component.role}</td><td><code>${component.className || 'Unavailable'}</code></td>
                            <td>${this._componentOrigin(component)}</td></tr>`)}</tbody>
                    </table></div>
                    <p class="note">For CDI producers, the class shown declares the producer; its returned implementation is not instantiated for inspection.
                        No repository queries are made. YAML clients only seed the default repository and are not a list of clients in a custom repository.</p>`
                    : html`<p class="note">${this._runtime.status === 'SELECT_TENANT' ? 'Select a tenant to inspect its components.'
                        : 'Components are unavailable; no instance is created for inspection.'}</p>`}
            </section>
            <section class="assembly" aria-labelledby="signing-heading">
                <h3 id="signing-heading">Signing keys</h3>
                ${signing ? html`
                    <p>${sources[signing.source] || 'Source unavailable'}</p>
                    ${signing.provider ? html`<p><code>${signing.provider.className || 'Provider unavailable'}</code>
                        <span class="note provider-origin">${this._componentOrigin(signing.provider)}</span></p>` : ''}
                    ${signing.initialized ? html`
                        <p>Active signing key: <code>${signing.activeKeyId}</code></p>
                        <div class="table-scroll"><table aria-label="Public signing key identifiers">
                            <thead><tr><th>Public key ID</th><th>Algorithm</th></tr></thead>
                            <tbody>${signing.keys.map(key => html`<tr><td><code>${key.keyId}</code></td>
                                <td><code>${key.algorithm}</code></td></tr>`)}</tbody>
                        </table></div>` : html`<p class="note">No initialized contextual key manager is available.
                            Dev UI does not initialize it or invoke dependent producers.</p>`}
                    ${signing.source === 'EPHEMERAL' ? html`<p class="note">This key changes when the application restarts.</p>` : ''}
                    <p class="note">Only public identifiers and algorithms from the existing key manager are shown.
                        Refresh does not load key sources, generate keys or rotate them.</p>`
                    : html`<p class="note">Select an available tenant to inspect its initialized signing keys.</p>`}
            </section>`;
    }

    render() {
        return html`
            <h2>Authorization Server</h2>
            <p class="description">Installed routes and features come from build-time configuration.
                Issuer information is read from the running application.</p>
            <dl class="summary">
                <div><dt>HTTP root</dt><dd><code>${overview.httpRoot}</code></dd></div>
                <div><dt>Issuer routing</dt><dd>${overview.multipleIssuers ? 'Multiple issuers' : 'Single issuer'}</dd></div>
                <div><dt>Installed protocol endpoints</dt><dd>${overview.endpoints.length}</dd></div>
            </dl>
            <div class="features" aria-label="Build-time features">
                ${overview.features.map(feature => html`
                    <span class="feature ${feature.enabled ? 'enabled' : 'disabled'}">
                        ${feature.name}: ${feature.enabled ? 'enabled' : 'disabled'}
                    </span>`)}
            </div>
            <section class="runtime" aria-labelledby="runtime-heading">
                <h3 id="runtime-heading">Runtime issuer</h3>
                <div class="controls">
                    ${overview.multipleIssuers ? html`<label>Tenant
                        <select aria-label="Tenant" .value=${this._selectedTenant} @change=${this._selectTenant}>
                            <option value="">Select a tenant</option>
                            ${this._tenantIds.map(id => html`<option value=${id}>${id}</option>`)}
                        </select></label>` : ''}
                    <button @click=${this._loadRuntime} ?disabled=${this._loading}>Refresh runtime information</button>
                </div>
                <p role="status" class=${this._error ? 'error' : ''}>${this._runtimeMessage()}</p>
            </section>
            ${this._renderAssembly()}
            <p class="description">Published URLs below are derived from the configured issuer, before any discovery customizers.
                Development URLs use the current browser origin (<code>${window.location.origin}</code>).
                Read links inspect discovery documents or public signing keys on this development server.</p>
            ${overview.multipleIssuers && this._runtime?.status !== 'READY' ? html`
                <p class="description"><code>{issuer}</code> is a tenant placeholder; select a tenant to resolve these paths.</p>` : ''}
            <div class="table-scroll">
                <table>
                    <caption>Protocol endpoints</caption>
                    <thead><tr><th scope="col">Configuration / endpoint</th><th scope="col">HTTP methods</th>
                        <th scope="col">Endpoint addresses</th><th scope="col">Inspect locally</th></tr></thead>
                    <tbody>${overview.endpoints.map(endpoint => {
                        const path = this._localPath(endpoint);
                        const localUrl = path ? new URL(path, window.location.origin).href : null;
                        return html`
                        <tr>
                            <td><code>${endpoint.name}</code></td>
                            <td><span class="method">${endpoint.methods.join(', ')}</span>
                                ${endpoint.note ? html`<div class="note">${endpoint.note}</div>` : ''}</td>
                            <td><div class="address-label">Published URL (from issuer)</div><code>${this._publishedUrl(endpoint) || '—'}</code>
                                <div class="address-label">${localUrl ? 'Development URL' : 'Route template'}</div>
                                <code>${localUrl || endpoint.path}</code></td>
                            <td>${endpoint.readable && localUrl ? html`<a href=${localUrl} target="_blank" rel="noopener noreferrer"
                                aria-label=${`Read ${endpoint.name}`}>Read JSON ↗</a>` : '—'}</td>
                        </tr>`;
                    })}</tbody>
                </table>
            </div>`;
    }
}

customElements.define('qwc-authorization-server-overview', QwcAuthorizationServerOverview);
