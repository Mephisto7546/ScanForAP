#include <sys/param.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_http_server.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "CredentialsHTML.h"
#include "IndexHTML.h"

#define APSSID          "STIP4711"
#define APPASSWORD      "13011975"
#define APCHANNEL       6
#define APMAXCONNECTION 3
static const char APIP[4] = {192, 168, 50, 2};
static const char APGW[4] = {192, 168, 50, 1};
static const char APNM[4] = {255, 255, 255, 0};

#define DEFAULT_SCAN_LIST_SIZE 20

static const char* TSCAN = "scan";
static const char* TWBS  = "webserver";
static const char* TSTA  = "STA";

static char sAuthenticationMode[]="This is a placeholder for authentication";
static char STASSID[32];
static char STAPASSWORD[64];
#define ServerPort      80;

static void print_auth_mode(int authmode);
static httpd_handle_t  StartWebServer(void);
void ScanForAPs();
void InitWifiAP(void);
static void InitWebServer(void);
static httpd_handle_t  StartWebServer(void);
static void StopWebServer(httpd_handle_t Server);
static esp_err_t echo_post_handler(httpd_req_t* req);
static esp_err_t hello_get_handler(httpd_req_t *req);
static esp_err_t credentials_post_handler(httpd_req_t *req);
static esp_err_t index_get_handler(httpd_req_t *req);

static const httpd_uri_t indexhtml = {
  .uri = "/",
  .method = HTTP_GET,
  .handler = index_get_handler,
  .user_ctx = NULL
};
static esp_err_t index_get_handler(httpd_req_t *req) {
  httpd_resp_send(req, IndexHTML, strlen(IndexHTML));
  return ESP_OK;
}
static const httpd_uri_t hello = {
	.uri     = "/hello",
  .method  = HTTP_GET,
  .handler = hello_get_handler,
  /* Let's pass response string in user
  * context to demonstrate it's usage */
  .user_ctx = "Hello World!"
};
static esp_err_t hello_get_handler(httpd_req_t* req) {
  char*  buf;
  size_t buf_len;

  /* Get header value string length and allocate memory for length + 1,
   * extra byte for null termination */
  buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
  if(buf_len > 1) {
    buf = malloc(buf_len);
    /* Copy null terminated value string into buffer */
    if(httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TSCAN, "Found header => Host: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
  if(buf_len > 1) {
    buf = malloc(buf_len);
    if(httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TSCAN, "Found header => Test-Header-2: %s", buf);
    }
    free(buf);
  }

  buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
  if(buf_len > 1) {
    buf = malloc(buf_len);
    if(httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
      ESP_LOGI(TSCAN, "Found header => Test-Header-1: %s", buf);
    }
    free(buf);
  }

  /* Read URL query string length and allocate memory for length + 1,
   * extra byte for null termination */
  buf_len = httpd_req_get_url_query_len(req) + 1;
  if(buf_len > 1) {
    buf = malloc(buf_len);
    if(httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
      ESP_LOGI(TSCAN, "Found URL query => %s", buf);
      char param[32];
      /* Get value of expected key from query string */
      if(httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TSCAN, "Found URL query parameter => query1=%s", param);
      }
      if(httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TSCAN, "Found URL query parameter => query3=%s", param);
      }
      if(httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
        ESP_LOGI(TSCAN, "Found URL query parameter => query2=%s", param);
      }
    }
    free(buf);
  }

  /* Set some custom headers */
  httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
  httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

  /* Send response with custom headers and body set as the
   * string passed in user context*/
  const char* resp_str = (const char*)req->user_ctx;
  httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

  /* After sending the HTTP response the old HTTP request
   * headers are lost. Check if HTTP request headers can be read now. */
  if(httpd_req_get_hdr_value_len(req, "Host") == 0) {
    ESP_LOGI(TSCAN, "Request headers lost");
  }
  return ESP_OK;
}
static const httpd_uri_t Credentials = {
  .uri 		= "/credentials.html", 
  .method 	= HTTP_POST, 
  .handler 	= credentials_post_handler, 
  .user_ctx 	= NULL
};
static esp_err_t credentials_post_handler(httpd_req_t *req){
  char buf[100];
  int  ret, remaining = req->content_len;

  while(remaining > 0) {
    /* Read the data for the request */
    if((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if(ret == HTTPD_SOCK_ERR_TIMEOUT) {
	/* Retry receiving if timeout occurred */
	continue;
      }
      return ESP_FAIL;
    }

    /* Log data received */
    ESP_LOGI(TSCAN, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TSCAN, "%.*s", ret, buf);
    ESP_LOGI(TSCAN, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}
static const httpd_uri_t echo = {
  .uri 		= "/echo", 
  .method 	= HTTP_POST, 
  .handler 	= echo_post_handler, 
  .user_ctx 	= NULL
};
static esp_err_t echo_post_handler(httpd_req_t* req) {
  char buf[100];
  int  ret, remaining = req->content_len;

  while(remaining > 0) {
    /* Read the data for the request */
    if((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
      if(ret == HTTPD_SOCK_ERR_TIMEOUT) {
	/* Retry receiving if timeout occurred */
	continue;
      }
      return ESP_FAIL;
    }

    /* Send back the same data */
    httpd_resp_send_chunk(req, buf, ret);
    remaining -= ret;

    /* Log data received */
    ESP_LOGI(TSCAN, "=========== RECEIVED DATA ==========");
    ESP_LOGI(TSCAN, "%.*s", ret, buf);
    ESP_LOGI(TSCAN, "====================================");
  }

  // End response
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}
static esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err){
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

static void print_auth_mode(int authmode) {
  switch(authmode) {
  case WIFI_AUTH_OPEN:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_OPEN");
    break;
  case WIFI_AUTH_WEP:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WEP");
    break;
  case WIFI_AUTH_WPA_PSK:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA_PSK");
    break;
  case WIFI_AUTH_WPA2_PSK:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA2_PSK");
    break;
  case WIFI_AUTH_WPA_WPA2_PSK:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA_WPA2_PSK");
    break;
  case WIFI_AUTH_WPA2_ENTERPRISE:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA2_ENTERPRISE");
    break;
  case WIFI_AUTH_WPA3_PSK:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA3_PSK");
    break;
  case WIFI_AUTH_WPA2_WPA3_PSK:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA2_WPA3_PSK");
    break;
  default:
    strcpy(sAuthenticationMode,"\tWIFI_AUTH_WPA2_WPA3_PSK");
//     ESP_LOGI(TSCAN, "Authmode \tWIFI_AUTH_UNKNOWN");
    break;

  }
}
// static void print_cipher_type(int pairwise_cipher, int group_cipher) {
//   switch(pairwise_cipher) {
//   case WIFI_CIPHER_TYPE_NONE:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_NONE");
//     break;
//   case WIFI_CIPHER_TYPE_WEP40:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP40");
//     break;
//   case WIFI_CIPHER_TYPE_WEP104:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP104");
//     break;
//   case WIFI_CIPHER_TYPE_TKIP:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP");
//     break;
//   case WIFI_CIPHER_TYPE_CCMP:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_CCMP");
//     break;
//   case WIFI_CIPHER_TYPE_TKIP_CCMP:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
//     break;
//   default:
//     ESP_LOGI(TSCAN, "Pairwise Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
//     break;
//   }
//   switch(group_cipher) {
//   case WIFI_CIPHER_TYPE_NONE:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_NONE");
//     break;
//   case WIFI_CIPHER_TYPE_WEP40:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_WEP40");
//     break;
//   case WIFI_CIPHER_TYPE_WEP104:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_WEP104");
//     break;
//   case WIFI_CIPHER_TYPE_TKIP:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP");
//     break;
//   case WIFI_CIPHER_TYPE_CCMP:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_CCMP");
//     break;
//   case WIFI_CIPHER_TYPE_TKIP_CCMP:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
//     break;
//   default:
//     ESP_LOGI(TSCAN, "Group Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
//     break;
//   }
// }

static void event_handler(void* arg, esp_event_base_t event_base,int32_t event_id, void* event_data){
  httpd_handle_t *Server = (httpd_handle_t*)arg;

  if(event_base == WIFI_EVENT){
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
      wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
      ESP_LOGI(TSTA, "station "MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
      wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
      ESP_LOGI(TSTA, "station "MACSTR" leave, AID=%d", MAC2STR(event->mac), event->aid);
      if(*Server == NULL){
        *Server = StartWebServer();
      }
    }
    else if(event_id == WIFI_EVENT_STA_DISCONNECTED){
      if(*Server){
        ESP_LOGI(TWBS,"Stopping web server");
        StopWebServer(*Server);
        *Server = NULL;
      }
    }
  }
  else if(event_base == IP_EVENT){
    if(event_id == IP_EVENT_STA_GOT_IP){
      if(*Server == NULL){
        ESP_LOGI(TWBS,"Starting web server");
        *Server = StartWebServer();
      }
    }
    if(event_id == IP_EVENT_AP_STAIPASSIGNED){
      if(*Server == NULL){
        ESP_LOGI(TWBS,"Starting web server");
        *Server = StartWebServer();
      }
    }
  }
}
void ScanForAPs() {
  // ESP_ERROR_CHECK(esp_netif_init());
  // ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_t* sta_netif = esp_netif_create_default_wifi_sta();
  assert(sta_netif);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  uint16_t         number = DEFAULT_SCAN_LIST_SIZE;
  wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
  uint16_t         ap_count = 0;
  memset(ap_info, 0, sizeof(ap_info));
  
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_wifi_scan_start(NULL, true);
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
  ESP_LOGI(TSCAN, "Total APs scanned = %u", ap_count);

//   for(int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < ap_count); i++) {
//     ESP_LOGI(TSCAN, "SSID \t\t%s", ap_info[i].ssid);
//     ESP_LOGI(TSCAN, "RSSI \t\t%d", ap_info[i].rssi);
//     print_auth_mode(ap_info[i].authmode);
//     if(ap_info[i].authmode != WIFI_AUTH_WEP) {
//       print_cipher_type(ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
//     }
//     ESP_LOGI(TSCAN, "Channel \t\t%d\n", ap_info[i].primary);
//   }

  ESP_LOGI(TSCAN, "Found %d access points:\n", ap_count);
  ESP_LOGI(TSCAN, "               SSID              | Channel | RSSI |         MAC       |         ENCRYPTION        ");
  ESP_LOGI(TSCAN,"----------------------------------------------------------------------------------------------------");
  for(int i = 0; i < ap_count; i++){
    print_auth_mode(ap_info[i].authmode);
    ESP_LOGI(TSCAN, "%32s | %7d | %4d | %2x:%2x:%2x:%2x:%2x:%2x | %s  ", ap_info[i].ssid, ap_info[i].primary, ap_info[i].rssi, *ap_info[i].bssid, *(ap_info[i].bssid + 1), *(ap_info[i].bssid + 2),
             *(ap_info[i].bssid + 3), *(ap_info[i].bssid + 4), *(ap_info[i].bssid + 5), sAuthenticationMode);
    ESP_LOGI(TSCAN,"----------------------------------------------------------------------------------------------------");
  }
}
void InitWifiAP(void) {
  esp_netif_t        *CurrentAP = NULL;
  esp_netif_ip_info_t IPInfoSet;
  char                sIPBuffer[0x100];
  char                sGWBuffer[0x100];
  char                sNMBuffer[0x100];

  // ESP_ERROR_CHECK(esp_netif_init());
  // ESP_ERROR_CHECK(esp_event_loop_create_default());
  CurrentAP = esp_netif_create_default_wifi_ap();
  
  esp_netif_dhcps_stop(CurrentAP);
  IP4_ADDR(&IPInfoSet.ip, APIP[0],APIP[1],APIP[2],APIP[3]);
  IP4_ADDR(&IPInfoSet.gw, APGW[0],APGW[1],APGW[2],APGW[3]);
  IP4_ADDR(&IPInfoSet.netmask, APNM[0],APNM[1],APNM[2],APNM[3]);
  // IP4_ADDR(&IPInfoSet.ip, 192,168,50,2);
  // IP4_ADDR(&IPInfoSet.gw, 192,168,50,1);
  // IP4_ADDR(&IPInfoSet.netmask, 255,255,255,0);
  esp_netif_set_ip_info(CurrentAP, &IPInfoSet); //set static IP
  esp_netif_dhcps_start(CurrentAP);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));

  wifi_config_t wifi_config = {
    .ap = {
      .ssid           = APSSID,
      .ssid_len       = strlen(APSSID),
      .channel        = APCHANNEL,
      .password       = APPASSWORD,
      .max_connection = APMAXCONNECTION,
      .authmode       = WIFI_AUTH_WPA_WPA2_PSK
    },
  };
  if(strlen(APPASSWORD) == 0) {
    wifi_config.ap.authmode = WIFI_AUTH_OPEN;
  }

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));

  ESP_ERROR_CHECK(esp_wifi_start());
  esp_netif_get_ip_info(CurrentAP, &IPInfoSet);
  ESP_LOGI(TSCAN, "AP init finished. SSID:%s password:%s channel:%d", APSSID, APPASSWORD, APCHANNEL);
  ESP_LOGI(TSCAN,"IP-Address: %s Gateway: %s NetMask: %s", 
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.ip.addr)), sIPBuffer, sizeof(sIPBuffer)), 
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.gw.addr)), sGWBuffer, sizeof(sGWBuffer)),
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.netmask.addr)), sNMBuffer, sizeof(sNMBuffer)));
}
static void InitWebServer(void){
  static httpd_handle_t Server = NULL;

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,IP_EVENT_STA_GOT_IP,&event_handler,&Server));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&event_handler,&Server));

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &event_handler, &Server));

  // Server = StartWebServer();
}
static httpd_handle_t StartWebServer(void){
  httpd_handle_t Server 	= NULL;
  httpd_config_t WSConfig	= HTTPD_DEFAULT_CONFIG();
  WSConfig.server_port    = ServerPort;
  WSConfig.lru_purge_enable	= true;

  ESP_LOGI(TSCAN,"Startin web server on port: '%d'", WSConfig.server_port);
  if(httpd_start(&Server, &WSConfig) == ESP_OK){
    ESP_LOGI(TSCAN,"Registering URI handlers");
    httpd_register_uri_handler(Server,&indexhtml);
    httpd_register_uri_handler(Server,&Credentials);
    httpd_register_uri_handler(Server,&hello);
    httpd_register_uri_handler(Server,&echo);
    httpd_register_err_handler(Server, HTTPD_404_NOT_FOUND, &http_404_error_handler);
    return Server;
  }
  ESP_LOGI(TSCAN, "Error starting server!");
  return NULL;	
}
static void StopWebServer(httpd_handle_t Server){
  httpd_stop(Server);   	
}

void app_main() {
  // initialize NVS
  esp_err_t ret = nvs_flash_init();
  if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  
  ScanForAPs();
  InitWifiAP();
  InitWebServer();
}
