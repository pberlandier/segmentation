@echo off
setlocal EnableDelayedExpansion

:: Skip over function definitions
goto :main

:: Function definitions
:setup_registry_credentials
echo Setting up registry credentials in namespace: %NAMESPACE%

:: Get registry token
for /f "tokens=*" %%a in ('oc whoami -t') do set TOKEN=%%a
if "!TOKEN!"=="" (
    echo Failed to get OpenShift token. Please ensure you're logged in.
    exit /b 1
)

:: Login to registry
echo Logging into OpenShift registry...
oc registry login 2>nul

:: Check if secret already exists
oc get secret registry-credentials -n %NAMESPACE% >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    echo Registry credentials secret already exists, updating...
    oc delete secret registry-credentials -n %NAMESPACE%
) else (
    echo Creating new registry credentials secret...
)

:: Create registry credentials secret
for /f "tokens=*" %%a in ('oc whoami') do set USERNAME=%%a
oc create secret docker-registry registry-credentials ^
    --docker-server=image-registry.openshift-image-registry.svc:5000 ^
    --docker-username=!USERNAME! ^
    --docker-password=!TOKEN! ^
    -n %NAMESPACE% 2>nul

:: Check if secret is linked to default service account
for /f "tokens=*" %%a in ('oc get sa default -n %NAMESPACE% -o jsonpath^={.imagePullSecrets[*].name}') do set EXISTING_SECRETS=%%a
echo !EXISTING_SECRETS! | findstr /C:"registry-credentials" >nul
if !ERRORLEVEL! NEQ 0 (
    echo Linking registry-credentials secret to default service account...
    oc secrets link default registry-credentials --for=pull -n %NAMESPACE%
) else (
    echo Secret already linked to default service account
)
exit /b 0

:main
:: Main script starts here
:: Prompt for namespace first
set /p NAMESPACE="Input Namespace: "
echo Selected namespace: %NAMESPACE%

:: Switch to the namespace immediately
oc project %NAMESPACE%

:: Call setup_registry_credentials just once
call :setup_registry_credentials

:: Confirm service name
set SERVICE_NAME=cc-application-approval
set BASE_URL=apps.sandbox-m2.ll9k.p1.openshiftapps.com
:: Remove /auth from the base URL since it will be added in the endpoints
:: Normal Keycloak Deployment uncomment
::set KEYCLOAK_BASE_URL=keycloak-%NAMESPACE%.%BASE_URL%
set KEYCLOAK_BASE_URL=keycloak-timothywuthenow-dev.%BASE_URL%

:: Keycloak configuration
set REALM=jbpm-openshift
set CLIENT_ID=task-console
set ADMIN_USERNAME=admin
set /p ADMIN_PASSWORD="Enter Keycloak admin password: "

echo Keycloak Base URL is: %KEYCLOAK_BASE_URL%
set /p CONFIRM="Confirm service name (%SERVICE_NAME%)? [Y/n]: "
if /i "%CONFIRM%"=="n" (
    set /p SERVICE_NAME="Enter new service name: "
)

:: Derive console names from service name
set TASK_CONSOLE_NAME=%SERVICE_NAME%-task-console
set MGMT_CONSOLE_NAME=%SERVICE_NAME%-management-console

:: Function to get Keycloak access token
echo Attempting to get token from: https://%KEYCLOAK_BASE_URL%/auth/realms/master/protocol/openid-connect/token

:: Using curl to get token (Windows 10 has curl built-in)
curl -s -k -X POST "https://%KEYCLOAK_BASE_URL%/auth/realms/master/protocol/openid-connect/token" ^
  -H "Content-Type: application/x-www-form-urlencoded" ^
  -d "username=%ADMIN_USERNAME%" ^
  -d "password=%ADMIN_PASSWORD%" ^
  -d "grant_type=password" ^
  -d "client_id=admin-cli" > token_response.tmp

:: Parse the token from response
for /f "tokens=2 delims=:," %%a in ('type token_response.tmp ^| findstr "access_token"') do (
    set TOKEN=%%a
    :: Remove quotes and leading/trailing spaces
    set TOKEN=!TOKEN:"=!
    set TOKEN=!TOKEN: =!
)

if "!TOKEN!"=="" (
    echo Failed to obtain access token. Check your credentials and Keycloak configuration.
    type token_response.tmp
    del token_response.tmp
    exit /b 1
)

echo Successfully obtained access token

:: Update client configuration
echo Fetching clients from realm %REALM%...
curl -s -k -X GET "https://%KEYCLOAK_BASE_URL%/auth/admin/realms/%REALM%/clients" ^
  -H "Authorization: Bearer !TOKEN!" ^
  -H "Content-Type: application/json" > clients_response.tmp

:: Find client ID (simplified parsing)
for /f "tokens=2 delims=:," %%a in ('type clients_response.tmp ^| findstr "id.*%CLIENT_ID%"') do (
    set CLIENT_ID_INTERNAL=%%a
    set CLIENT_ID_INTERNAL=!CLIENT_ID_INTERNAL:"=!
    set CLIENT_ID_INTERNAL=!CLIENT_ID_INTERNAL: =!
)

if "!CLIENT_ID_INTERNAL!"=="" (
    echo Client %CLIENT_ID% not found in realm %REALM%.
    type clients_response.tmp
    del clients_response.tmp
    exit /b 1
)

:: Create update payload for client configuration
set NEW_REDIRECT_URI=https://%TASK_CONSOLE_NAME%-%NAMESPACE%.%BASE_URL%/*
set NEW_WEB_ORIGIN=https://%TASK_CONSOLE_NAME%-%NAMESPACE%.%BASE_URL%

echo {^
    "publicClient": true,^
    "directAccessGrantsEnabled": true,^
    "standardFlowEnabled": true,^
    "implicitFlowEnabled": false,^
    "serviceAccountsEnabled": false,^
    "redirectUris": ["%NEW_REDIRECT_URI%"],^
    "webOrigins": ["%NEW_WEB_ORIGIN%"]^
} > update_payload.json

:: Update client configuration
curl -s -k -X PUT "https://%KEYCLOAK_BASE_URL%/auth/admin/realms/%REALM%/clients/%CLIENT_ID_INTERNAL%" ^
  -H "Authorization: Bearer !TOKEN!" ^
  -H "Content-Type: application/json" ^
  -d @update_payload.json

:: Clean up temporary files
del token_response.tmp clients_response.tmp update_payload.json

:: Delete existing deployments if they exist
oc delete deployment %SERVICE_NAME% --ignore-not-found=true
oc delete deployment %TASK_CONSOLE_NAME% --ignore-not-found=true
oc delete deployment %MGMT_CONSOLE_NAME% --ignore-not-found=true

:: Build and deploy the application with image pull secrets
call mvn clean package ^
    -Dquarkus.container-image.build=true ^
    -Dquarkus.kubernetes-client.namespace=%NAMESPACE% ^
    -Dquarkus.openshift.deploy=true ^
    -Dquarkus.openshift.expose=true ^
    -Dquarkus.application.name=%SERVICE_NAME% ^
    -Dkogito.service.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL% ^
    -Dkogito.jobs-service.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL% ^
    -Dkogito.dataindex.http.url=https://%SERVICE_NAME%-%NAMESPACE%.%BASE_URL% ^
    -Dquarkus.openshift.image-pull-secrets=registry-credentials

:: Get the route host
for /f "tokens=*" %%a in ('oc get route %SERVICE_NAME% -o jsonpath^={.spec.host}') do set ROUTE_HOST=%%a

:: Set environment variables
oc set env deployment/%SERVICE_NAME% ^
    KOGITO_SERVICE_URL=https://%ROUTE_HOST% ^
    KOGITO_JOBS_SERVICE_URL=https://%ROUTE_HOST% ^
    KOGITO_DATAINDEX_HTTP_URL=https://%ROUTE_HOST%

:: Patch the route for edge TLS termination
oc patch route %SERVICE_NAME% -p "{\"spec\":{\"tls\":{\"termination\":\"edge\"}}}"

:: Deploy Task Console
echo apiVersion: apps/v1> task-console.yaml
echo kind: Deployment>> task-console.yaml
echo metadata:>> task-console.yaml
echo   name: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   namespace: %NAMESPACE%>> task-console.yaml
echo spec:>> task-console.yaml
echo   replicas: 1>> task-console.yaml
echo   selector:>> task-console.yaml
echo     matchLabels:>> task-console.yaml
echo       app: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   template:>> task-console.yaml
echo     metadata:>> task-console.yaml
echo       labels:>> task-console.yaml
echo         app: %TASK_CONSOLE_NAME%>> task-console.yaml
echo     spec:>> task-console.yaml
echo       imagePullSecrets:>> task-console.yaml
echo       - name: registry-credentials>> task-console.yaml
echo       containers:>> task-console.yaml
echo       - name: task-console>> task-console.yaml
echo         image: quay.io/bamoe/task-console:9.1.0-ibm-0001>> task-console.yaml
echo         imagePullPolicy: Always>> task-console.yaml
echo         ports:>> task-console.yaml
echo         - containerPort: 8080>> task-console.yaml
echo         env:>> task-console.yaml
echo         - name: RUNTIME_TOOLS_TASK_CONSOLE_KOGITO_ENV_MODE>> task-console.yaml
echo           value: "PROD">> task-console.yaml
echo         - name: RUNTIME_TOOLS_TASK_CONSOLE_DATA_INDEX_ENDPOINT>> task-console.yaml
echo           value: "https://%ROUTE_HOST%/graphql">> task-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL>> task-console.yaml
echo           value: "https://%KEYCLOAK_BASE_URL%/auth/realms/%REALM%/.well-known/openid-configuration">> task-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_URL>> task-console.yaml
echo           value: "https://%KEYCLOAK_BASE_URL%/auth">> task-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_REALM>> task-console.yaml
echo           value: "%REALM%">> task-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID>> task-console.yaml
echo           value: "%CLIENT_ID%">> task-console.yaml
echo --->> task-console.yaml
echo apiVersion: v1>> task-console.yaml
echo kind: Service>> task-console.yaml
echo metadata:>> task-console.yaml
echo   name: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   namespace: %NAMESPACE%>> task-console.yaml
echo spec:>> task-console.yaml
echo   selector:>> task-console.yaml
echo     app: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   ports:>> task-console.yaml
echo   - port: 8080>> task-console.yaml
echo     targetPort: 8080>> task-console.yaml
echo --->> task-console.yaml
echo apiVersion: route.openshift.io/v1>> task-console.yaml
echo kind: Route>> task-console.yaml
echo metadata:>> task-console.yaml
echo   name: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   namespace: %NAMESPACE%>> task-console.yaml
echo spec:>> task-console.yaml
echo   to:>> task-console.yaml
echo     kind: Service>> task-console.yaml
echo     name: %TASK_CONSOLE_NAME%>> task-console.yaml
echo   port:>> task-console.yaml
echo     targetPort: 8080>> task-console.yaml
echo   tls:>> task-console.yaml
echo     termination: edge>> task-console.yaml

oc apply -f task-console.yaml
del task-console.yaml

:: Deploy Management Console
echo apiVersion: apps/v1> mgmt-console.yaml
echo kind: Deployment>> mgmt-console.yaml
echo metadata:>> mgmt-console.yaml
echo   name: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   namespace: %NAMESPACE%>> mgmt-console.yaml
echo spec:>> mgmt-console.yaml
echo   replicas: 1>> mgmt-console.yaml
echo   selector:>> mgmt-console.yaml
echo     matchLabels:>> mgmt-console.yaml
echo       app: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   template:>> mgmt-console.yaml
echo     metadata:>> mgmt-console.yaml
echo       labels:>> mgmt-console.yaml
echo         app: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo     spec:>> mgmt-console.yaml
echo       imagePullSecrets:>> mgmt-console.yaml
echo       - name: registry-credentials>> mgmt-console.yaml
echo       containers:>> mgmt-console.yaml
echo       - name: management-console>> mgmt-console.yaml
echo         image: quay.io/bamoe/management-console:9.1.0-ibm-0001>> mgmt-console.yaml
echo         imagePullPolicy: Always>> mgmt-console.yaml
echo         ports:>> mgmt-console.yaml
echo         - containerPort: 8080>> mgmt-console.yaml
echo         env:>> mgmt-console.yaml
echo         - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_KOGITO_ENV_MODE>> mgmt-console.yaml
echo           value: "DEV">> mgmt-console.yaml
echo         - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_DATA_INDEX_ENDPOINT>> mgmt-console.yaml
echo           value: "https://%ROUTE_HOST%/graphql">> mgmt-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL>> mgmt-console.yaml
echo           value: "https://%KEYCLOAK_BASE_URL%/auth/realms/%REALM%/.well-known/openid-configuration">> mgmt-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_URL>> mgmt-console.yaml
echo           value: "https://%KEYCLOAK_BASE_URL%/auth">> mgmt-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_REALM>> mgmt-console.yaml
echo           value: "%REALM%">> mgmt-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID>> mgmt-console.yaml
echo           value: "management-console">> mgmt-console.yaml
echo         - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_SECRET>> mgmt-console.yaml
echo           value: fBd92XRwPlWDt4CSIIDHSxbcB1w0p3jm>> mgmt-console.yaml
echo --->> mgmt-console.yaml
echo apiVersion: v1>> mgmt-console.yaml
echo kind: Service>> mgmt-console.yaml
echo metadata:>> mgmt-console.yaml
echo   name: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   namespace: %NAMESPACE%>> mgmt-console.yaml
echo spec:>> mgmt-console.yaml
echo   selector:>> mgmt-console.yaml
echo     app: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   ports:>> mgmt-console.yaml
echo   - port: 8080>> mgmt-console.yaml
echo     targetPort: 8080>> mgmt-console.yaml
echo --->> mgmt-console.yaml
echo apiVersion: route.openshift.io/v1>> mgmt-console.yaml
echo kind: Route>> mgmt-console.yaml
echo metadata:>> mgmt-console.yaml
echo   name: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   namespace: %NAMESPACE%>> mgmt-console.yaml
echo spec:>> mgmt-console.yaml
echo   to:>> mgmt-console.yaml
echo     kind: Service>> mgmt-console.yaml
echo     name: %MGMT_CONSOLE_NAME%>> mgmt-console.yaml
echo   port:>> mgmt-console.yaml
echo     targetPort: 8080>> mgmt-console.yaml
echo   tls:>> mgmt-console.yaml
echo     termination: edge>> mgmt-console.yaml

oc apply -f mgmt-console.yaml
del mgmt-console.yaml
:: Display final URLs
for /f "tokens=*" %%a in ('oc get route %SERVICE_NAME% -o jsonpath^={.spec.host}') do (
    echo Deployment completed. Application is available at https://%%a/q/swagger-ui
)
for /f "tokens=*" %%a in ('oc get route %TASK_CONSOLE_NAME% -o jsonpath^={.spec.host}') do (
    echo Task Console is available at https://%%a
)
for /f "tokens=*" %%a in ('oc get route %MGMT_CONSOLE_NAME% -o jsonpath^={.spec.host}') do (
    echo Management Console is available at https://%%a
)

endlocal