# Prompt for namespace
$NAMESPACE = Read-Host -Prompt "Input Namespace"

# Confirm service name
$SERVICE_NAME = "cc-application-approval"
$BASE_URL = "apps.tzrosa-8bc90xwq.pzcn.p1.openshiftapps.com"
$KEYCLOAK_URL = "keycloak-keycloak.$BASE_URL/auth"
$CONFIRM = Read-Host -Prompt "Confirm service name ($SERVICE_NAME)? [Y/n]"
if ($CONFIRM -match '^[Nn]$') {
    $SERVICE_NAME = Read-Host -Prompt "Enter new service name"
}

# Set the OpenShift project
oc project $NAMESPACE

# Build and deploy the application
mvn clean package `
    "-Dquarkus.container-image.build=true" `
    "-Dquarkus.kubernetes-client.namespace=$NAMESPACE" `
    "-Dquarkus.openshift.deploy=true" `
    "-Dquarkus.openshift.expose=true" `
    "-Dquarkus.application.name=$SERVICE_NAME" `
    "-Dkogito.service.url=https://$SERVICE_NAME-$NAMESPACE.$BASE_URL" `
    "-Dkogito.jobs-service.url=https://$SERVICE_NAME-$NAMESPACE.$BASE_URL" `
    "-Dkogito.dataindex.http.url=https://$SERVICE_NAME-$NAMESPACE.$BASE_URL"

# Get the route host
$ROUTE_HOST = oc get route $SERVICE_NAME -o jsonpath='{.spec.host}'

# Set environment variables
oc set env deployment/$SERVICE_NAME `
    KOGITO_SERVICE_URL="https://$ROUTE_HOST" `
    KOGITO_JOBS_SERVICE_URL="https://$ROUTE_HOST" `
    KOGITO_DATAINDEX_HTTP_URL="https://$ROUTE_HOST"

# Configure the route for HTTPS
oc patch route $SERVICE_NAME --type=json -p '[
    {"op": "add", "path": "/spec/tls", "value": 
        {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
    },
    {"op": "replace", "path": "/spec/port/targetPort", "value": "8080-tcp"}
]'

# Deploy Task Console
$taskConsoleYaml = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: task-console
spec:
  replicas: 1
  selector:
    matchLabels:
      app: task-console
  template:
    metadata:
      labels:
        app: task-console
    spec:
      containers:
      - name: task-console
        image: quay.io/bamoe/task-console:9.1.0-ibm-0001
        ports:
        - containerPort: 8080
        env:
        - name: RUNTIME_TOOLS_TASK_CONSOLE_KOGITO_ENV_MODE
          value: "PROD"
        - name: RUNTIME_TOOLS_TASK_CONSOLE_DATA_INDEX_ENDPOINT
          value: "https://$ROUTE_HOST/graphql"
        - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL
          value: "https://$KEYCLOAK_URL/realms/jbpm-openshift/.well-known/openid-configuration"
        - name: KOGITO_CONSOLES_KEYCLOAK_URL
          value: "https://$KEYCLOAK_URL"
        - name: KOGITO_CONSOLES_KEYCLOAK_REALM
          value: "jbpm-openshift"
        - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID
          value: "task-console"
---
apiVersion: v1
kind: Service
metadata:
  name: task-console
spec:
  selector:
    app: task-console
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: task-console
spec:
  to:
    kind: Service
    name: task-console
  port:
    targetPort: 8080
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
"@

$taskConsoleYaml | oc apply -f -

# Deploy Management Console
$managementConsoleYaml = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: management-console
spec:
  replicas: 1
  selector:
    matchLabels:
      app: management-console
  template:
    metadata:
      labels:
        app: management-console
    spec:
      containers:
      - name: management-console
        image: quay.io/bamoe/management-console:9.1.0-ibm-0001
        ports:
        - containerPort: 8080
        env:
        - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_KOGITO_ENV_MODE
          value: "DEV"
        - name: RUNTIME_TOOLS_MANAGEMENT_CONSOLE_DATA_INDEX_ENDPOINT
          value: "https://$ROUTE_HOST/graphql"
        - name: KOGITO_CONSOLES_KEYCLOAK_HEALTH_CHECK_URL
          value: "https://$KEYCLOAK_URL/realms/jbpm-openshift/.well-known/openid-configuration"
        - name: KOGITO_CONSOLES_KEYCLOAK_URL
          value: "https://$KEYCLOAK_URL"
        - name: KOGITO_CONSOLES_KEYCLOAK_REALM
          value: "jbpm-openshift"
        - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_ID
          value: "management-console"
        - name: KOGITO_CONSOLES_KEYCLOAK_CLIENT_SECRET
          value: fBd92XRwPlWDt4CSIIDHSxbcB1w0p3jm
---
apiVersion: v1
kind: Service
metadata:
  name: management-console
spec:
  selector:
    app: management-console
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: management-console
spec:
  to:
    kind: Service
    name: management-console
  port:
    targetPort: 8080
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
"@

$managementConsoleYaml | oc apply -f -

Write-Host "Deployment completed. Application is available at https://$ROUTE_HOST/q/swagger-ui"
Write-Host "Task Console is available at https://$(oc get route task-console -o jsonpath='{.spec.host}')"
Write-Host "Management Console is available at https://$(oc get route management-console -o jsonpath='{.spec.host}')"