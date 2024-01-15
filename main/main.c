#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_spiffs.h"
#include "nvs_flash.h"
#include "esp_vfs.h"
#include "esp_http_server.h"
#include "cJSON.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "ScanedAPsHTML.h"

#define APSSID          "STIP4711"
#define APPASSWORD      "13011975"
#define APCHANNEL       6
#define APMAXCONNECTION 3
static const char APIP[4] = {192, 168, 50, 2};
static const char APGW[4] = {192, 168, 50, 1};
static const char APNM[4] = {255, 255, 255, 0};
// #define STA_SSID        "BueroTed2"
// #define STA_PASSWORD    "AB8206026337488977787MO63"
// #define STA_SSID              "Wireless"
// #define STA_PASSWORD          "4197438864651226"
static EventGroupHandle_t WifiEventGroup;
static int                STAConnectCounter = 0;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define WIFI_SCAN_DONE_BIT BIT2
#define WIFI_STA_MAX_RETRY 5
#define ServerPort         80
#define DEFAULT_SCAN_LIST_SIZE 20
static char sAuthenticationMode[]="This is a placeholder for authentication";

#define MAXURIS 8
typedef struct httpd_uri ur;
ur AllURIs[MAXURIS];

static const char* TAG = "ScanWifi";;

cJSON*       JSRObject = NULL;
static char *cJSONString;

/* Max length a file path can have on storage */
#define FILE_PATH_MAX         (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)
/* Scratch buffer size */
#define SCRATCH_BUFSIZE       8192
struct TFileServerData {
  /* Base path of file storage */
  char base_path[ESP_VFS_PATH_MAX + 1];

  /* Scratch buffer for temporary storage during file transfer */
  char scratch[SCRATCH_BUFSIZE];
};
static struct TFileServerData *server_data = NULL;
// ==============================================================================
//                             PROTOTYPES
// ==============================================================================
static void print_auth_mode(int authmode);
void ScanForAPs();
void InitWifiAP(void);
esp_err_t InitWifiSTA(void);
static void InitAndRegisterUris(httpd_handle_t Server);
static void event_handler(void* arg, esp_event_base_t event_base,int32_t event_id, void* event_data);
static void InitWebServer(void);
static httpd_handle_t  StartWebServer(const char *base_path);
static void StopWebServer(httpd_handle_t Server);
static esp_err_t InitSpiffs(void);
static esp_err_t GeneralGETHandler(httpd_req_t *req);
static esp_err_t GeneralPUTHandler(httpd_req_t *req);
void ScanForAPs();
void InitESP32();

// ==============================================================================
//                             WIFI SETUP
// ==============================================================================
void InitWifiAPSTA(void) {
  esp_netif_t        *CurrentAP = NULL;
  esp_netif_t        *CurrentSTA= NULL;
  esp_netif_ip_info_t IPInfoSet;
  char                sIPBuffer[0x100];
  char                sGWBuffer[0x100];
  char                sNMBuffer[0x100];

  WifiEventGroup = xEventGroupCreate();
  CurrentAP = esp_netif_create_default_wifi_ap();
  assert(CurrentAP);
  CurrentSTA= esp_netif_create_default_wifi_sta();
  assert(CurrentSTA);
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
  
  // SETUP AP PART
  esp_netif_dhcps_stop(CurrentAP);
  IP4_ADDR(&IPInfoSet.ip, APIP[0],APIP[1],APIP[2],APIP[3]);
  IP4_ADDR(&IPInfoSet.gw, APGW[0],APGW[1],APGW[2],APGW[3]);
  IP4_ADDR(&IPInfoSet.netmask, APNM[0],APNM[1],APNM[2],APNM[3]);
  
  esp_netif_set_ip_info(CurrentAP, &IPInfoSet); //set static IP
  esp_netif_dhcps_start(CurrentAP);
 
  esp_event_handler_instance_t instance_any_id;
  esp_event_handler_instance_t instance_got_ip;
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

  wifi_config_t WifiAPConfig = {
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
    WifiAPConfig.ap.authmode = WIFI_AUTH_OPEN;
  }
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &WifiAPConfig));

  // SETUP STA PART (only a subset is defined since STA is only used in Scan)
  wifi_config_t WifiSTAConfig ={
    .sta = {
      .ssid = "",
      .password = ""
    },
  };
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &WifiSTAConfig));

  ESP_ERROR_CHECK(esp_wifi_start());
  esp_netif_get_ip_info(CurrentAP, &IPInfoSet);
  ESP_LOGI(TAG, "AP init finished. SSID:%s password:%s channel:%d", APSSID, APPASSWORD, APCHANNEL);
  ESP_LOGI(TAG,"IP-Address: %s Gateway: %s NetMask: %s", 
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.ip.addr)), sIPBuffer, sizeof(sIPBuffer)), 
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.gw.addr)), sGWBuffer, sizeof(sGWBuffer)),
    esp_ip4addr_ntoa((esp_ip4_addr_t*)(&(IPInfoSet.netmask.addr)), sNMBuffer, sizeof(sNMBuffer)));
  
  ESP_LOGI(TAG, "Wifi APSTA is done!");
}
static void InitAndRegisterUris(httpd_handle_t Server){
  AllURIs[0].uri = "/favicon.ico";
  AllURIs[0].handler = GeneralGETHandler;
  AllURIs[0].method = HTTP_GET;
  AllURIs[0].user_ctx = server_data;
  AllURIs[1].uri = "/"; 
  AllURIs[1].handler = GeneralGETHandler;
  AllURIs[1].method = HTTP_GET;
  AllURIs[1].user_ctx = server_data;
  AllURIs[2].uri = "/WifiNeutral.png"; 
  AllURIs[2].handler = GeneralGETHandler;
  AllURIs[2].method = HTTP_GET;
  AllURIs[2].user_ctx = server_data;
  AllURIs[3].uri = "/WifiLV1.png";
  AllURIs[3].handler = GeneralGETHandler;
  AllURIs[3].method = HTTP_GET;
  AllURIs[3].user_ctx = server_data;
  AllURIs[4].uri = "/WifiLV2.png";
  AllURIs[4].handler = GeneralGETHandler;
  AllURIs[4].method = HTTP_GET;
  AllURIs[4].user_ctx = server_data;
  AllURIs[5].uri = "/WifiLV3.png";
  AllURIs[5].handler = GeneralGETHandler;
  AllURIs[5].method = HTTP_GET;
  AllURIs[5].user_ctx = server_data;
  AllURIs[6].uri = "/WifiLV4.png";
  AllURIs[6].handler = GeneralGETHandler;
  AllURIs[6].method = HTTP_GET;
  AllURIs[6].user_ctx = server_data;
  AllURIs[7].uri = "/GetScanResults";
  AllURIs[7].handler = GeneralGETHandler;
  AllURIs[7].method = HTTP_GET;
  AllURIs[7].user_ctx = server_data;

  for(uint8_t a = 0; a < MAXURIS; a++) {
    httpd_register_uri_handler(Server, &AllURIs[a]);
  }
}
static esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err){
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}
static void event_handler(void* arg, esp_event_base_t event_base,int32_t event_id, void* event_data){
  httpd_handle_t *Server = (httpd_handle_t*)arg;

  if(event_base == WIFI_EVENT){
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
      wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
      ESP_LOGI(TAG, "station "MACSTR" join, AID=%d", MAC2STR(event->mac), event->aid);
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
      wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
      ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d", MAC2STR(event->mac), event->aid);
    }
    else if(event_id == WIFI_EVENT_STA_CONNECTED){
      xEventGroupSetBits(WifiEventGroup, WIFI_CONNECTED_BIT);
    }
    else if(event_id == WIFI_EVENT_STA_DISCONNECTED) {
      wifi_event_sta_disconnected_t* sta_disconnect_evt = (wifi_event_sta_disconnected_t*)event_data;
      ESP_LOGI(TAG, "wifi disconnect reason:%d", sta_disconnect_evt->reason);
      xEventGroupClearBits(WifiEventGroup, WIFI_CONNECTED_BIT);
    
      if(STAConnectCounter < WIFI_STA_MAX_RETRY) {
        esp_wifi_connect();
        STAConnectCounter++;
        ESP_LOGI(TAG, "retry to connect to the AP");
      }
      else {
        xEventGroupSetBits(WifiEventGroup, WIFI_FAIL_BIT);
        ESP_LOGI(TAG, "connect to the AP fail");
        if(*Server) {
          ESP_LOGI(TAG, "Stopping web server");
          StopWebServer(*Server);
          *Server = NULL;
        }
      }
    }
    else if(event_id == WIFI_EVENT_STA_START){
      esp_wifi_connect();
    }
    else if(event_id == WIFI_EVENT_SCAN_DONE){
      xEventGroupSetBits(WifiEventGroup, WIFI_SCAN_DONE_BIT);
    }
  }
  else if(event_base == IP_EVENT){
    if(event_id == IP_EVENT_STA_GOT_IP){
      ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
      ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
      STAConnectCounter = 0;

      if(*Server == NULL){
        ESP_LOGI(TAG,"Starting web server");
        *Server = StartWebServer("/spiffs");
      }
    }
    if(event_id == IP_EVENT_AP_STAIPASSIGNED){
      if(*Server == NULL){
        ESP_LOGI(TAG,"Starting web server");
        *Server = StartWebServer("/spiffs");
      }
    }
  }
}
// ==============================================================================
//                           WEBSERVER SETUP
// ==============================================================================
static void InitWebServer(void){
  static httpd_handle_t Server = NULL;

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,IP_EVENT_STA_GOT_IP,&event_handler,&Server));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&event_handler,&Server));

  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &event_handler, &Server));

}
static httpd_handle_t StartWebServer(const char *base_path){
  httpd_handle_t Server 	= NULL;
  httpd_config_t WSConfig	= HTTPD_DEFAULT_CONFIG();
  WSConfig.server_port    	= ServerPort;
  WSConfig.lru_purge_enable	= true;

  /* Validate file storage base path */
  if (!base_path || strcmp(base_path, "/spiffs") != 0) {
      ESP_LOGE(TAG, "File server presently supports only '/spiffs' as base path");
      return NULL;
  }

  if (server_data) {
      ESP_LOGE(TAG, "File server already started");
      return NULL;
  }

  /* Allocate memory for server data */
  server_data = calloc(1, sizeof(struct TFileServerData));
  if (!server_data) {
      ESP_LOGE(TAG, "Failed to allocate memory for server data");
      return NULL;
  }
  strlcpy(server_data->base_path, base_path, sizeof(server_data->base_path));

  
  ESP_LOGI(TAG,"Startin web server on port: '%d'", WSConfig.server_port);
  if(httpd_start(&Server, &WSConfig) == ESP_OK){
    ESP_LOGI(TAG,"Registering URI handlers");
    InitAndRegisterUris(Server);
    httpd_register_err_handler(Server, HTTPD_404_NOT_FOUND, &http_404_error_handler);
    return Server;
  }
  ESP_LOGI(TAG, "Error starting server!");
  return NULL;	
}
static void StopWebServer(httpd_handle_t Server){
  httpd_stop(Server);   	
}
static esp_err_t InitSpiffs(void){
  ESP_LOGI(TAG, "Initializing SPIFFS");

  esp_vfs_spiffs_conf_t conf = {
    .base_path = "/spiffs",
    .partition_label = NULL,
    .max_files = 5, // number of files that can be opened at the same time
    .format_if_mount_failed = true
  };

  esp_err_t ret = esp_vfs_spiffs_register(&conf);
  if(ret != ESP_OK) {
    if(ret == ESP_FAIL){
      ESP_LOGE(TAG, "Failed to mount or format filesystem");
    }
    else if(ret == ESP_ERR_NOT_FOUND) {
      ESP_LOGE(TAG, "Failed to find SPIFFS partition");
    }
    else {
      ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
    }
    return ESP_FAIL;
  }

  size_t total = 0, used = 0;
  ret = esp_spiffs_info(NULL, &total, &used);
  if(ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
  return ESP_OK;
}
#define IS_FILE_EXT(_FileName, ext) (strcasecmp(&_FileName[strlen(_FileName) - sizeof(ext) + 1], ext) == 0)
static esp_err_t GeneralGETHandler(httpd_req_t *req) {
  
  if(strcmp(req->uri, "/") == 0) {
    httpd_resp_set_type(req, "text/html");
    extern const unsigned char index_html_start[] asm("_binary_index_html_start");
    extern const unsigned char index_html_end[] asm("_binary_index_html_end");
    const size_t               index_html_size = (index_html_end - index_html_start);
    httpd_resp_send(req, (const char *)index_html_start, index_html_size);
  }
  else if(strcmp("/favicon.ico", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_png_start");
    extern const unsigned char favicon_ico_end[]   asm("_binary_favicon_png_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
    // httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/favicon.ico URI is not available");
  }
  else if(strcmp("/WifiNeutral.png", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char WifiNeutral_png_start[] asm("_binary_WifiNeutral_png_start");
    extern const unsigned char WifiNeutral_png_end[] asm("_binary_WifiNeutral_png_end");
    const size_t               WifiNeutral_png_size = (WifiNeutral_png_end - WifiNeutral_png_start);
    httpd_resp_send(req, (const char *)WifiNeutral_png_start, WifiNeutral_png_size);
  }
  else if(strcmp("/WifiLV1.png", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char WifiLV1_png_start[] asm("_binary_WifiLV1_png_start");
    extern const unsigned char WifiLV1_png_end[] asm("_binary_WifiLV1_png_end");
    const size_t               WifiLV1_png_size = (WifiLV1_png_end - WifiLV1_png_start);
    httpd_resp_send(req, (const char *)WifiLV1_png_start, WifiLV1_png_size);
  }
  else if(strcmp("/WifiLV2.png", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char WifiLV2_png_start[] asm("_binary_WifiLV2_png_start");
    extern const unsigned char WifiLV2_png_end[] asm("_binary_WifiLV2_png_end");
    const size_t               WifiLV2_png_size = (WifiLV2_png_end - WifiLV2_png_start);
    httpd_resp_send(req, (const char *)WifiLV2_png_start, WifiLV2_png_size);
  }
  else if(strcmp("/WifiLV3.png", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char WifiLV3_png_start[] asm("_binary_WifiLV3_png_start");
    extern const unsigned char WifiLV3_png_end[] asm("_binary_WifiLV3_png_end");
    const size_t               WifiLV3_png_size = (WifiLV3_png_end - WifiLV3_png_start);
    httpd_resp_send(req, (const char *)WifiLV3_png_start, WifiLV3_png_size);
  }
  else if(strcmp("/WifiLV4.png", req->uri) == 0){
    httpd_resp_set_type(req, "image/png");
    extern const unsigned char WifiLV4_png_start[] asm("_binary_WifiLV4_png_start");
    extern const unsigned char WifiLV4_png_end[] asm("_binary_WifiLV4_png_end");
    const size_t               WifiLV4_png_size = (WifiLV4_png_end - WifiLV4_png_start);
    httpd_resp_send(req, (const char *)WifiLV4_png_start, WifiLV4_png_size);
  }
  else if(strcmp("/GetScanResults", req->uri) == 0){
    ScanForAPs();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, cJSONString, strlen(cJSONString));
  }
  else if(strcmp("/getcreds.html", req->uri) == 0){
    httpd_resp_set_type(req, "text/html");
    extern const unsigned char credsinput_html_start[] asm("_binary_credsinput_html_start");
    extern const unsigned char credsinput_html_end[] asm("_binary_credsinput_html_end");
    const size_t               credsinput_html_size = (credsinput_html_end - credsinput_html_start);
    httpd_resp_send(req, (const char *)credsinput_html_start, credsinput_html_size);
  }
  
  return ESP_OK;
}
static esp_err_t GeneralPUTHandler(httpd_req_t *req) {
  char* pchr;
  pchar = strstr(req->uri, "/setcreds");
  if(pchar != NULL){
    
  }
}
// ==============================================================================
//                           SCAN FOR ACCESSPOINTS
// ==============================================================================
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

void ScanForAPs(){
  uint16_t         MaxAPCount = 10;
  wifi_ap_record_t APRecordSets[10];
  uint16_t         APCount    = 0;
  memset(APRecordSets, 0, sizeof(APRecordSets));
  
  xEventGroupClearBits(WifiEventGroup, WIFI_SCAN_DONE_BIT);
  esp_wifi_scan_start(NULL, true);
  // wait till scan is done
  EventBits_t bits = xEventGroupWaitBits(WifiEventGroup, WIFI_SCAN_DONE_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
  if(bits & WIFI_SCAN_DONE_BIT){
    xEventGroupClearBits(WifiEventGroup, WIFI_SCAN_DONE_BIT);
  }
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&MaxAPCount, APRecordSets));
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&APCount));
  ESP_LOGI(TAG, "Total APs scanned = %u", APCount);
  
  // create JSON JSRObject object
  JSRObject = cJSON_CreateObject();
  cJSON *APs = NULL;     // main array
  cJSON *AP = NULL;      // array element

  // if(JSRObject == NULL){
  //   ESP_LOGE(TAG,"failed to add main object");
  // }

  // add APCount as first element into the JSON object
  cJSON_AddNumberToObject(JSRObject, "NumberOfAPs", APCount);
  // create array to hold ap information
	APs = cJSON_CreateArray();
	if (APs == NULL) {
		ESP_LOGE(TAG, "failed to create array");
	}
	cJSON_AddItemToObject(JSRObject,"APs",APs);
  
  // fill aps objects with according data
  for (int i=0;i<APCount;i++) {
		// dynamically create array for number of APs
    AP = cJSON_CreateObject();
    if(AP == NULL){
      ESP_LOGE(TAG,"failed to create array element");
    }
    cJSON_AddItemToArray(APs,AP);

    cJSON_AddNumberToObject(AP, "channel", APRecordSets[i].primary);
    cJSON_AddStringToObject(AP, "ssid", (char*)APRecordSets[i].ssid);
		cJSON_AddNumberToObject(AP, "rssi", APRecordSets[i].rssi);
	}

	cJSONString = cJSON_Print(JSRObject);
	ESP_LOGI(TAG, "ScanedAPList\n%s",cJSONString);
  JSRObject = NULL;

//   for(int i = 0; (i < DEFAULT_SCAN_LIST_SIZE) && (i < APCount); i++) {
//     ESP_LOGI(TAG, "SSID \t\t%s", APRecordSets[i].ssid);
//     ESP_LOGI(TAG, "RSSI \t\t%d", APRecordSets[i].rssi);
//     print_auth_mode(APRecordSets[i].authmode);
//     if(APRecordSets[i].authmode != WIFI_AUTH_WEP) {
//       print_cipher_type(APRecordSets[i].pairwise_cipher, APRecordSets[i].group_cipher);
//     }
//     ESP_LOGI(TAG, "Channel \t\t%d\n", APRecordSets[i].primary);
//   }

  ESP_LOGI(TAG, "Found %d access points:\n", APCount);
  ESP_LOGI(TAG, "               SSID              | Channel | RSSI |         MAC       |         ENCRYPTION        ");
  ESP_LOGI(TAG,"----------------------------------------------------------------------------------------------------");
  for(int i = 0; i < APCount; i++){
    print_auth_mode(APRecordSets[i].authmode);
    ESP_LOGI(TAG, "%32s | %7d | %4d | %2x:%2x:%2x:%2x:%2x:%2x | %s  ", APRecordSets[i].ssid, APRecordSets[i].primary, APRecordSets[i].rssi, *APRecordSets[i].bssid, *(APRecordSets[i].bssid + 1), *(APRecordSets[i].bssid + 2),
             *(APRecordSets[i].bssid + 3), *(APRecordSets[i].bssid + 4), *(APRecordSets[i].bssid + 5), sAuthenticationMode);
    ESP_LOGI(TAG,"----------------------------------------------------------------------------------------------------");
  }
}


void InitESP32(){
  // initialize NVS
  esp_err_t ret = nvs_flash_init();
  if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  
  ESP_ERROR_CHECK(InitSpiffs());

  // ScanForAPs();
  // if(InitWifiSTA() == ESP_FAIL){
    InitWifiAPSTA();
  // }
  InitWebServer();
}
void app_main() {
  InitESP32();
}
