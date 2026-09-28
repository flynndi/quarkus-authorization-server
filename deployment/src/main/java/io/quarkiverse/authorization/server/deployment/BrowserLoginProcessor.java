package io.quarkiverse.authorization.server.deployment;

import jakarta.inject.Singleton;

import org.jboss.jandex.DotName;

import io.quarkiverse.authorization.server.runtime.AuthorizationServerRecorder;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.BrowserLoginSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.DefaultLoginPage;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.RunTimeConfigurationDefaultBuildItem;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.deployment.spi.RouteBuildItem;
import io.quarkus.vertx.http.runtime.RouteConstants;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;

/** Installs the optional default login page and its Quarkus Form integration. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class BrowserLoginProcessor {

    @BuildStep
    AdditionalBeanBuildItem defaultBrowserLogin(
            AuthorizationServerBuildTimeConfig config,
            VertxHttpBuildTimeConfig httpConfig,
            BuildProducer<RunTimeConfigurationDefaultBuildItem> defaults) {
        if (!config.defaultLoginPageEnabled()) {
            return null;
        }
        if (!httpConfig.auth().form()) {
            throw new ConfigurationException("quarkus.authorization-server.default-login-page-enabled requires "
                    + "quarkus.http.auth.form.enabled=true");
        }
        defaults.produce(new RunTimeConfigurationDefaultBuildItem("quarkus.http.auth.form.landing-page",
                "${quarkus.http.auth.form.login-page}"));
        defaults.produce(new RunTimeConfigurationDefaultBuildItem("quarkus.http.auth.form.http-only-cookie", "true"));
        defaults.produce(new RunTimeConfigurationDefaultBuildItem("quarkus.http.auth.form.cookie-same-site", "lax"));
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(DefaultLoginPage.class, BrowserLoginSecurityConfiguration.class)
                .setDefaultScope(DotName.createSimple(Singleton.class))
                .setUnremovable().build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerDefaultLoginPage(
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder,
            BeanContainerBuildItem beans,
            BuildProducer<RouteBuildItem> routes) {
        if (!config.defaultLoginPageEnabled()) {
            return;
        }
        // Form page locations are runtime configuration and are absolute URLs on this server,
        // independent of quarkus.http.root-path. The handler only claims the configured pages.
        routes.produce(RouteBuildItem.newAbsoluteRoute("/*")
                .withOrder(RouteConstants.ROUTE_ORDER_BEFORE_DEFAULT)
                .withRouteCustomizer(recorder.getEndpointRoute())
                .withRequestHandler(recorder.defaultLoginPage(beans.getValue()))
                .build());
    }
}
