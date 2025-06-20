import json
import os

import httpx
from fastapi import FastAPI, Depends, HTTPException, Request, Response, APIRouter
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception
)
from app.services.keycloak import get_current_user , logger

router = APIRouter(tags=["keycloak"])


# Fix 1: Properly parse the SERVICE_MAP from environment variable
def parse_service_map():
    """Parse SERVICE_MAP from environment variable"""
    services_map_str = os.getenv("SERVICES_MAP", "{}")

    try:
        # If it's a JSON string, parse it
        if services_map_str.startswith("{"):
            return json.loads(services_map_str)
        else:
            # If it's in the format you showed, parse it manually
            # SERVICES_MAP={"mission": "http://localhost:8050", "achat": "http://localhost:8051", "stock": "http://localhost:8052"}
            services_map_str = services_map_str.strip()
            if services_map_str.startswith('SERVICES_MAP='):
                services_map_str = services_map_str[13:]  # Remove 'SERVICES_MAP='

            # Use eval carefully (only for trusted config)
            return eval(services_map_str)

    except Exception as e:
        logger.error(f"Error parsing SERVICES_MAP: {e}")
        # Fallback to hardcoded values
        return {
            "mission": "http://localhost:8050",
            "achat": "http://localhost:8051",
            "stock": "http://localhost:8052"
        }


# Initialize SERVICE_MAP
SERVICE_MAP = parse_service_map()


# Fix 2: Add validation
def validate_service_map():
    """Validate that SERVICE_MAP is properly configured"""
    if not isinstance(SERVICE_MAP, dict):
        raise ValueError(f"SERVICE_MAP must be a dictionary, got {type(SERVICE_MAP)}")

    if not SERVICE_MAP:
        raise ValueError("SERVICE_MAP cannot be empty")

    logger.info(f"SERVICE_MAP loaded successfully: {SERVICE_MAP}")


# Call validation on startup
validate_service_map()


# Fonction pour déterminer si une exception httpx doit être retentée
def is_retryable_httpx_exception(exception):
    """Détermine si une exception httpx doit être retentée"""
    if isinstance(exception, httpx.TimeoutException):
        return True
    if isinstance(exception, httpx.ConnectError):
        return True
    if isinstance(exception, httpx.HTTPStatusError):
        return exception.response.status_code in [500, 502, 503, 504]
    return False


# REMPLACEZ votre endpoint proxy par celui-ci :
@router.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(service: str, path: str, request: Request, user=Depends(get_current_user)):
    # Fix 3: Add debug logging
    logger.debug(f"SERVICE_MAP type: {type(SERVICE_MAP)}")
    logger.debug(f"SERVICE_MAP content: {SERVICE_MAP}")
    logger.debug(f"Looking for service: '{service}'")

    # Fix 4: Better error handling for service lookup
    if not isinstance(SERVICE_MAP, dict):
        logger.error(f"SERVICE_MAP is not a dictionary! Type: {type(SERVICE_MAP)}, Value: {SERVICE_MAP}")
        raise HTTPException(
            status_code=500,
            detail="Service configuration error: SERVICE_MAP is not properly configured"
        )

    if service not in SERVICE_MAP:
        available_services = list(SERVICE_MAP.keys())
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service}' not found. Available services: {available_services}"
        )

    url = f"{SERVICE_MAP[service]}/{path}"

    # Prepare headers
    headers = dict(request.headers)
    headers_to_remove = ["host", "content-length", "connection"]
    for header in headers_to_remove:
        if header in headers:
            del headers[header]

    # Add user context headers
    headers["X-User-ID"] = user.get("sub", "")
    headers["X-User-Email"] = user.get("email", "")
    headers["X-User-Roles"] = ",".join(user.get("realm_access", {}).get("roles", []))
    headers["X-User-Name"] = user.get("name", "")

    # Forward the Keycloak token
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
        print(f"✅ Forwarding Authorization header to {service}")
    else:
        # If token is in cookies, convert to Authorization header
        access_token = request.cookies.get("access_token")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
            print(f"✅ Converting cookie token to Authorization header for {service}")

    method = request.method

    # Handle request content
    content = None
    if method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                content = await request.json()
            elif "application/x-www-form-urlencoded" in content_type:
                form = await request.form()
                content = dict(form)
            elif "multipart/form-data" in content_type:
                form = await request.form()
                content = dict(form)
            else:
                content = await request.body()
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error parsing request body: {str(e)}"
            )

    logger.info(f"Proxying {method} request to {url}")

    # Call the retry function
    return await make_request_with_retry(method, url, content, headers, service)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception(is_retryable_httpx_exception),
    before=lambda retry_state: logger.info(
        f"Making request attempt #{retry_state.attempt_number}"
    ),
    before_sleep=lambda retry_state: logger.warning(
        f"Request failed. Retrying in {retry_state.next_action.sleep:.2f} seconds. "
        f"Attempt {retry_state.attempt_number}/3. "
    )
)
async def make_request_with_retry(method: str, url: str, content, headers: dict, service: str):
    """Function that makes HTTP request with retry logic"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.debug(f"Making {method} request to {url}")

            response = await client.request(
                method,
                url,
                content=content,
                headers=headers,
                follow_redirects=True
            )

            # If status code is 5xx, raise exception to trigger retry
            if response.status_code in [500, 502, 503, 504]:
                logger.warning(f"Received retryable status code {response.status_code} from {url}")
                raise httpx.HTTPStatusError(
                    message=f"Server error: {response.status_code}",
                    request=response.request,
                    response=response
                )

            # Return the response from the microservice
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )

    except httpx.TimeoutException as e:
        logger.error(f"Timeout error while connecting to {url}: {str(e)}")
        raise

    except httpx.ConnectError as e:
        logger.error(f"Connection error while connecting to {url}: {str(e)}")
        raise

    except httpx.HTTPStatusError as e:
        # If it's a retryable status code, re-raise for retry
        if e.response.status_code in [500, 502, 503, 504]:
            logger.error(f"HTTP status error from {url}: {e.response.status_code}")
            raise
        else:
            # For other status codes (4xx), don't retry
            logger.warning(f"Non-retryable HTTP error from {url}: {e.response.status_code}")
            return Response(
                content=e.response.content,
                status_code=e.response.status_code,
                headers=dict(e.response.headers),
                media_type=e.response.headers.get("content-type")
            )

    except Exception as e:
        # For any other unexpected exception, don't retry
        logger.error(f"Unexpected error while connecting to {url}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error forwarding request to service '{service}': {str(e)}"
        )