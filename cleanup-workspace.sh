#!/bin/bash

# Define protected services
PROTECTED_SERVICES=("keycloak" "postgresql" "bamoe-canvas" "bamoe-maven-repo" "bamoe-extended-services" "bamoe-cors-proxy")

# Get all services
SERVICES=$(oc get svc -o name)

# Delete non-protected services
for service in $SERVICES; do
    SERVICE_NAME=$(echo $service | cut -d'/' -f2)
    if [[ ! " ${PROTECTED_SERVICES[@]} " =~ " ${SERVICE_NAME} " ]]; then
        echo "Deleting service: $SERVICE_NAME"
        oc delete svc "$SERVICE_NAME"
        # Delete associated resources
        oc delete deployment "$SERVICE_NAME" 2>/dev/null
        oc delete route "$SERVICE_NAME" 2>/dev/null
    fi
done

# Clean up management and task consoles that aren't part of protected services
for route in $(oc get routes -o name | grep -E "management-console|task-console"); do
    ROUTE_NAME=$(echo $route | cut -d'/' -f2)
    if [[ ! " ${PROTECTED_SERVICES[@]} " =~ " ${ROUTE_NAME%-*} " ]]; then
        echo "Deleting route: $ROUTE_NAME"
        oc delete route "$ROUTE_NAME"
        oc delete svc "$ROUTE_NAME" 2>/dev/null
        oc delete deployment "$ROUTE_NAME" 2>/dev/null
    fi
done
