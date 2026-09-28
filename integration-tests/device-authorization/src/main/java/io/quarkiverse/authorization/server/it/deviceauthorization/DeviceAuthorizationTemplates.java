package io.quarkiverse.authorization.server.it.deviceauthorization;

import io.quarkus.qute.CheckedTemplate;
import io.quarkus.qute.TemplateInstance;

@CheckedTemplate
public final class DeviceAuthorizationTemplates {

    private DeviceAuthorizationTemplates() {
    }

    public static native TemplateInstance index();

    public static native TemplateInstance login(boolean authenticationFailed);
}
