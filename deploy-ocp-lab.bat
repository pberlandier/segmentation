@echo off
setlocal EnableDelayedExpansion

:: Prompt for namespace
set /p NAMESPACE="Input Namespace: "

:: Confirm service name
set SERVICE_NAME=cc-application-approval
set BASE_URL=apps.sandbox-m2.ll9k.p1.openshiftapps.com
set KEYCLOAK_URL=keycloak-%NAMESPACE%.%BASE_URL%/auth
echo Keycloak URL is: %KEYCLOAK_URL%
set /p CONFIRM="Confirm service name (%SERVICE_NAME%)? [Y/n]: "
if /i "%CONFIRM%"=="n" (
    set /p SERVICE_NAME="Enter new service name: "
)

:: Set the OpenShift project
oc project %NAMESPACE%

:: Build and deploy the application
call mvn clean package ^
-Dquarkus.container-image.build=true ^
-Dquarkus.kubernetes-client.namespace=%NAMESPACE% ^
-Dquarkus.openshift.deploy=true ^
-Dquarkus.openshift.expose=true ^
-Dquarkus.application.name=%SERVICE_NAME% ^
-Dkogito.service.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL% ^
-Dkogito.jobs-service.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL% ^
-Dkogito.dataindex.http.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL%

:: Get the route host
for /f "tokens=*" %%i in ('oc get route %SERVICE_NAME% -o jsonpath^={.spec.host}') do set ROUTE_HOST=%%i

:: Set environment variables
oc set env deployment/%SERVICE_NAME% ^
KOGITO_SERVICE_URL=https://%ROUTE_HOST% ^
KOGITO_JOBS_SERVICE_URL=https://%ROUTE_HOST% ^
KOGITO_DATAINDEX_HTTP_URL=https://%ROUTE_HOST%

:: Patch the route for edge TLS termination
oc patch route %SERVICE_NAME% -p "{\"spec\":{\"tls\":{\"termination\":\"edge\"}}}"

:: Deploy Task Console
(
echo apiVersion: apps/v1
echo kind: Deployment
echo metadata:
echo   name: task-console
echo spec:
echo   replicas: 1
echo   selector:
echo     matchLabels:
echo       app: task-console
echo   template:
echo     metadata:
echo       labels:
echo         app: task-console
echo     spec:
echo       containers:
echo       - name: task-console
echo         image: quay.io/bamoe/task-console:9.1.0-ibm-0001
echo         ports:
echo         - containerPort: 8080
echo         env:
echo         - name: RUNTIME_TOOLS_TASK_CONSOLE_KOGITO_ENV_MODE
echo           value: "PROD"
echo         - name: RUNTIME_TOOLS_TASK_CONSOLE_DATA_INDEX_ENDPOINT
echo           value: "https://%ROUTE_HOST%/graphql"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL
echo           value: "https://%KEYCLOAK_URL%/realms/jbpm-openshift/.well-known/openid-configuration"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_URL
echo           value: "https://%KEYCLOAK_URL%"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_REALM
echo           value: "jbpm-openshift"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID
echo           value: "task-console"
echo ---
echo apiVersion: v1
echo kind: Service
echo metadata:
echo   name: task-console
echo spec:
echo   selector:
echo     app: task-console
echo   ports:
echo   - port: 8080
echo     targetPort: 8080
echo ---
echo apiVersion: route.openshift.io/v1
echo kind: Route
echo metadata:
echo   name: task-console
echo spec:
echo   to:
echo     kind: Service
echo     name: task-console
echo   port:
echo     targetPort: 8080
echo   tls:
echo     termination: edge
) > task-console.yaml
oc apply -f task-console.yaml
del task-console.yaml

:: Deploy Management Console
(
echo apiVersion: apps/v1
echo kind: Deployment
echo metadata:
echo   name: management-console
echo spec:
echo   replicas: 1
echo   selector:
echo     matchLabels:
echo       app: management-console
echo   template:
echo     metadata:
echo       labels:
echo         app: management-console
echo     spec:
echo       containers:
echo       - name: management-console
echo         image: quay.io/bamoe/management-console:9.1.0-ibm-0001
echo         ports:
echo         - containerPort: 8080
echo         env:
echo         - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_KOGITO_ENV_MODE
echo           value: "DEV"
echo         - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_DATA_INDEX_ENDPOINT
echo           value: "https://%ROUTE_HOST%/graphql"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL
echo           value: "https://%KEYCLOAK_URL%/realms/jbpm-openshift/.well-known/openid-configuration"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_URL
echo           value: "https://%KEYCLOAK_URL%"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_REALM
echo           value: "jbpm-openshift"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID
echo           value: "management-console"
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_SECRET
echo           value: fBd92XRwPlWDt4CSIIDHSxbcB1w0p3jm
echo ---
echo apiVersion: v1
echo kind: Service
echo metadata:
echo   name: management-console
echo spec:
echo   selector:
echo     app: management-console
echo   ports:
echo   - port: 8080
echo     targetPort: 8080
echo ---
echo apiVersion: route.openshift.io/v1
echo kind: Route
echo metadata:
echo   name: management-console
echo spec:
echo   to:
echo     kind: Service
echo     name: management-console
echo   port:
echo     targetPort: 8080
echo   tls:
echo     termination: edge
) > management-console.yaml
oc apply -f management-console.yaml
del management-console.yaml

:: Display final URLs
for /f "tokens=*" %%i in ('oc get route task-console -o jsonpath^={.spec.host}') do set TASK_CONSOLE_HOST=%%i
for /f "tokens=*" %%i in ('oc get route management-console -o jsonpath^={.spec.host}') do set MGMT_CONSOLE_HOST=%%i

echo Deployment completed. Application is available at https://%ROUTE_HOST%/q/swagger-ui
echo Task Console is available at https://%TASK_CONSOLE_HOST%
echo Management Console is available at https://%MGMT_CONSOLE_HOST%

endlocal
