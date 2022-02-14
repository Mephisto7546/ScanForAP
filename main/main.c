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

#define DEFAULT_SCAN_LIST_SIZE 20

static const char* TSCAN = "scan";
static const char* TWBS  = "webserver";
static const char* TSTA  = "STA";
static const char* JSON  = "JSON";
static const char* TAG   = "SPIFFS";
static char        cJSONString;

static char sAuthenticationMode[]="This is a placeholder for authentication";
static char STASSID[32];
static char STAPASSWORD[64];
#define ServerPort      80;

/* Max length a file path can have on storage */
#define FILE_PATH_MAX         (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)
/* Scratch buffer size */
#define SCRATCH_BUFSIZE       8192
char parsed[5][25];
char parse[100];
char size_ssid[35];
char ssid_get[30] = "ssid", pass_get[25] = "pass", conn_get[10] = "wifi";
struct TFileServerData {
  /* Base path of file storage */
  char base_path[ESP_VFS_PATH_MAX + 1];

  /* Scratch buffer for temporary storage during file transfer */
  char scratch[SCRATCH_BUFSIZE];
};


static void print_auth_mode(int authmode);
static httpd_handle_t  StartWebServer(void);
void ScanForAPs();
void InitWifiAP(void);
static void InitWebServer(void);
static httpd_handle_t  StartWebServer(void);
static void StopWebServer(httpd_handle_t Server);
static esp_err_t scan_get_handler(httpd_req_t *req);
static esp_err_t credentials_post_handler(httpd_req_t *req);
static esp_err_t index_get_handler(httpd_req_t *req);
cJSON *Create_array_of_anything(cJSON **objects,int array_num);

static esp_err_t connect_get_handler(httpd_req_t *req) {
  // just for the sake of it
  return ESP_OK;
}
static esp_err_t contact_resp_dir_html(httpd_req_t *req, const char *dirpath){
  // just for the sake of it
  return ESP_OK;
}
static esp_err_t about_resp_dir_html(httpd_req_t *req, const char *dirpath){
  // just for the sake of it
  return ESP_OK;
}
static esp_err_t WifiNeutral_get_handler(httpd_req_t *req) {
  extern const unsigned char WifiNeutral_png_start[] asm("_binary_WifiNeutral_png_start");
  extern const unsigned char WifiNeutral_png_end[] asm("_binary_WifiNeutral_png_end");
  const size_t               WifiNeutral_png_size = (WifiNeutral_png_end - WifiNeutral_png_start);
  httpd_resp_set_type(req, "image/png");
  httpd_resp_send(req, (const char *)WifiNeutral_png_start, WifiNeutral_png_size);
  return ESP_OK;
}
static esp_err_t WifiLV1_get_handler(httpd_req_t *req) {
  extern const unsigned char WifiLV1_png_start[] asm("_binary_WifiLV1_png_start");
  extern const unsigned char WifiLV1_png_end[] asm("_binary_WifiLV1_png_end");
  const size_t               WifiLV1_png_size = (WifiLV1_png_end - WifiLV1_png_start);
  httpd_resp_set_type(req, "image/png");
  httpd_resp_send(req, (const char *)WifiLV1_png_start, WifiLV1_png_size);
  return ESP_OK;
}
static esp_err_t WifiLV2_get_handler(httpd_req_t *req) {
  extern const unsigned char WifiLV2_png_start[] asm("_binary_WifiLV2_png_start");
  extern const unsigned char WifiLV2_png_end[] asm("_binary_WifiLV2_png_end");
  const size_t               WifiLV2_png_size = (WifiLV2_png_end - WifiLV2_png_start);
  httpd_resp_set_type(req, "image/png");
  httpd_resp_send(req, (const char *)WifiLV2_png_start, WifiLV2_png_size);
  return ESP_OK;
}
static esp_err_t WifiLV3_get_handler(httpd_req_t *req) {
  extern const unsigned char WifiLV3_png_start[] asm("_binary_WifiLV3_png_start");
  extern const unsigned char WifiLV3_png_end[] asm("_binary_WifiLV3_png_end");
  const size_t               WifiLV3_png_size = (WifiLV3_png_end - WifiLV3_png_start);
  httpd_resp_set_type(req, "image/png");
  httpd_resp_send(req, (const char *)WifiLV3_png_start, WifiLV3_png_size);
  return ESP_OK;
}
static esp_err_t WifiLV4_get_handler(httpd_req_t *req) {
  extern const unsigned char WifiLV4_png_start[] asm("_binary_WifiLV4_png_start");
  extern const unsigned char WifiLV4_png_end[] asm("_binary_WifiLV4_png_end");
  const size_t               WifiLV4_png_size = (WifiLV4_png_end - WifiLV4_png_start);
  httpd_resp_set_type(req, "image/png");
  httpd_resp_send(req, (const char *)WifiLV4_png_start, WifiLV4_png_size);
  return ESP_OK;
}
static const httpd_uri_t indexhtml = {
  .uri = "/",
  .method = HTTP_GET,
  .handler = index_get_handler,
  .user_ctx = NULL
};
static esp_err_t index_get_handler(httpd_req_t *req) {
  httpd_resp_send(req, ScanedAPsHTML, strlen(ScanedAPsHTML));
  return ESP_OK;
}
static const httpd_uri_t scan = {
	.uri     = "/scan",
  .method  = HTTP_GET,
  .handler = scan_get_handler,
  .user_ctx = NULL
};
static esp_err_t scan_get_handler(httpd_req_t* req) {
  httpd_resp_send(req, &cJSONString, strlen(&cJSONString));
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
uint16_t         ap_num = 10;
wifi_ap_record_t ap_records[10];
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
  
  
  // create JSON root object
  cJSON *root;
  root = cJSON_CreateObject();

  // add ap_count as first element into the JSON object
  cJSON_AddNumberToObject(root, "NumberOfAPs", ap_count);
  // dynamically create array for number of APs
  cJSON **APs = NULL;
	APs = (cJSON **)calloc(ap_count, sizeof(cJSON *));
	if (APs == NULL) {
		ESP_LOGE(JSON, "calloc fail");
	}
	for(int i=0;i<ap_count;i++) {
		APs[i] = cJSON_CreateObject();
	}
	cJSON *array;
	array = Create_array_of_anything(APs, ap_count);
  // fill aps objects with according data
  for (int i=0;i<ap_count;i++) {
		cJSON_AddNumberToObject(APs[i], "id", i);
    cJSON_AddNumberToObject(APs[i], "channel", ap_info[i].primary);
    cJSON_AddStringToObject(APs[i], "ssid", (char*)ap_info[i].ssid);
		cJSON_AddNumberToObject(APs[i], "rssi", ap_info[i].rssi);
	}
  // add array to previously created JSON object
  cJSON_AddItemToObject(root, "records", array);

	strcpy(cJSON_Print(root), &cJSONString);
	ESP_LOGI(JSON, "ScanedAPList\n%s",&cJSONString);
	cJSON_Delete(root);

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
cJSON *Create_array_of_anything(cJSON **objects,int array_num){
	cJSON *prev = 0;
	cJSON *root;
	root = cJSON_CreateArray();
	for (int i=0;i<array_num;i++) {
		if (!i)	{
			root->child=objects[i];
		} else {
			prev->next=objects[i];
			objects[i]->prev=prev;
		}
		prev=objects[i];
	}
	return root;
}
char *JSON_Types(int type) {
	if (type == cJSON_Invalid) return ("cJSON_Invalid");
	if (type == cJSON_False) return ("cJSON_False");
	if (type == cJSON_True) return ("cJSON_True");
	if (type == cJSON_NULL) return ("cJSON_NULL");
	if (type == cJSON_Number) return ("cJSON_Number");
	if (type == cJSON_String) return ("cJSON_String");
	if (type == cJSON_Array) return ("cJSON_Array");
	if (type == cJSON_Object) return ("cJSON_Object");
	if (type == cJSON_Raw) return ("cJSON_Raw");
	return NULL;
}
// prototype for deserialization
void JSON_Array(const cJSON * const array) {
	// int id = cJSON_GetObjectItem(array,"id")->valueint;
	// char *version = cJSON_GetObjectItem(array,"version")->valuestring;
	// int cores = cJSON_GetObjectItem(array,"cores")->valueint;
	// bool flag = cJSON_GetObjectItem(array,"flag")->valueint;
	// ESP_LOGI(TAG, "id=%d",id);
	// ESP_LOGI(TAG, "version=%s",version);
	// ESP_LOGI(TAG, "cores=%d",cores);
	// ESP_LOGI(TAG, "flag=%d",flag);
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
    httpd_register_uri_handler(Server,&scan);
    httpd_register_err_handler(Server, HTTPD_404_NOT_FOUND, &http_404_error_handler);
    return Server;
  }
  ESP_LOGI(TSCAN, "Error starting server!");
  return NULL;	
}
static void StopWebServer(httpd_handle_t Server){
  httpd_stop(Server);   	
}

static esp_err_t InitSpiffs(void) {
  ESP_LOGI(TSCAN, "Initializing SPIFFS");

  esp_vfs_spiffs_conf_t conf = {
    .base_path = "/spiffs",
    .partition_label = NULL,
    .max_files = 5, // This decides the maximum number of files that can be created on the storage
    .format_if_mount_failed = true
  };

  esp_err_t ret = esp_vfs_spiffs_register(&conf);
  if(ret != ESP_OK) {
    if(ret == ESP_FAIL) {
      ESP_LOGE(TSCAN, "Failed to mount or format filesystem");
    }
    else if(ret == ESP_ERR_NOT_FOUND) {
      ESP_LOGE(TSCAN, "Failed to find SPIFFS partition");
    }
    else {
      ESP_LOGE(TSCAN, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
    }
    return ESP_FAIL;
  }

  size_t total = 0, used = 0;
  ret = esp_spiffs_info(NULL, &total, &used);
  if(ret != ESP_OK) {
    ESP_LOGE(TSCAN, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    return ESP_FAIL;
  }

  ESP_LOGI(TSCAN, "Partition size: total: %d, used: %d", total, used);
  return ESP_OK;
}

static esp_err_t ask_resp_dir_html(httpd_req_t *req, const char *dirpath){

    httpd_resp_send_chunk(req,

                          "<tr>"
                          "<head>"
                          "<style>"
                          "body {background-color: whitesmoke;}"
                          "h1   {color: blue;}"
                          "p    {color: black;}"
                          "</style>"
                          "</head>"
                          "<body>"
                          "<p align=\"middle\"><img src=\"logo.png\" width=\"80\" height=\"81\" /></p>"

                          "</tr>"
                          "<tr>"
                          "<tr>"
                          "<p align=\"middle\"><img src=\"web.png\" alt=\"\" width=\"18\" height=\"18\" />"
                          "<a title=\"https://www.company_name.com/\" align=\"left\" href=\"https://www.company_name.com/\" target=\"_blank\" rel=\"noopener\" data-saferedirecturl=\"https://www.google.com/url?q=https://www.company_name.com/&amp;source=gmail&amp;ust=1547732724631000&amp;usg=AFQjCNHFlgAvZxHHJVtcGDzQgSFqupEjVA\">www.company_name.com</a>"
                          "</p>"
                          "</tr>"
                          "</tr>"
                          "<tr>"
                          "<p align=\"middle\"><img src=\"location.png\" alt=\"\" width=\"18\" height=\"18\" />"
                          "<strong>company_name</strong></p>"
                          "</tr>"
                          "<tr>"
                          "<p align=\"middle\">Address<br />Country</p>"

                          "<form name='loginForm'>"
                          "<table width='20%' bgcolor='A09F9F' align='center'>"
                          "<tr>"
                          "<td colspan=2>"
                          "<center><font size=4><b>Gateway Login Page</b></font></center>"

                          "</td>"

                          "</tr>"
                          "<td>Username:</td>"
                          "<td><input type='text' size=25 name='userid'><br></td>"
                          "</tr>"

                          "<tr>"
                          "<td>Password:</td>"
                          "<td><input type='Password' size=25 name='pwd'><br></td>"
                          "<br>"
                          "<br>"
                          "</tr>"
                          "<tr>"
                          "<td><input type='submit' onclick='check(this.form)' value='Login'></td>"
                          "</tr>"
                          "</table>"
                          "</form>"
                          "<script>"
                          "function check(form)"
                          "{"
                          "if(form.userid.value=='user' && form.pwd.value=='pass')"
                          "{"
                          "window.open('/index_html')"
                          "}"
                          "else"
                          "{"
                          " alert('Error Password or Username')/*displays error message*/"
                          "}"
                          "}"
                          "</script>"
                          "</body>",
                          -1);

    return ESP_OK;
}
static esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath){
    int signal_level[10] = {0};
    ScanForAPs();
    //  char signal[] = "0";

    /* Send HTML file header */
    httpd_resp_send_chunk(req,
                          "<!DOCTYPE html>"
                          "<html>"
                          "<head>"
                          "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /> "
                          "<style>"
                          "body {margin:0;}"

                          "ul {"
                          "  list-style-type: none;"
                          "  margin: 0;"
                          "  padding: 0;"
                          "  overflow: hidden;"
                          "  background-color: #333;"
                          "  position: fixed;"
                          "  top: 0;"
                          "  width: 100%;"
                          "}"
                          "li {"
                          "  float: left;"

                          "}"

                          "li:last-child {"
                          "  border-right: none;"
                          "}"

                          "li a {"
                          "  display: block;"
                          "  color: white;"
                          "  text-align: center;"
                          "  padding: 14px 16px;"
                          "  text-decoration: none;"
                          "}"

                          "li a:hover:not(.active) {"
                          "  background-color: #111;"
                          "}"

                          ".active {"
                          "  background-color: #e00a0a;"
                          "}"
                          "</style>"
                          "</head>"
                          "<head>"
                          "<style>"
                          "* {"
                          "  box-sizing: border-box;"
                          "}"

                          "input[type=text], select, textarea {"
                          "  width: 100%;"
                          "  padding: 5px 5px;"
                          "  border: 1px solid #ccc;"
                          "  border-radius: 4px;"
                          "  resize: vertical;"
                          "}"

                          "label {"
                          "  padding: 12px 12px 12px 0;"
                          "  display: inline-block;"
                          "}"

                          "input[type=submit] {"
                          "  background-color: #e00a0a;"
                          "  color: white;"
                          "  padding: 12px 20px;"
                          "  border: none;"
                          "  border-radius: 4px;"
                          "  cursor: pointer;"
                          "  float: right;"
                          "}"

                          "input[type=submit]:hover {"
                          "  background-color: #380a0a;"
                          "}"

                          ".container {"
                          "  border-radius: 5px;"
                          "  background-color: #f2f2f2;"
                          "  padding: 20px;"
                          "}"

                          ".col-25 {"
                          "  float: left;"
                          "  width: 25%;"
                          "  margin-top: 6px;"
                          "}"
                          ".col-15 {"
                          "  float: left;"
                          "  width: 15%;"
                          "  margin-top: 6px;"
                          "}"
                          ".col-75 {"
                          "  float: left;"
                          "  width: 75%;"
                          "  margin-top: 6px;"
                          "}"
                          ".col-55 {"
                          "  float: left;"
                          "  width: 55%;"
                          "  margin-top: 6px;"
                          "}"
                          "/* Clear floats after the columns */"
                          ".row:after {"
                          "  content: \"\";"
                          "  display: table;"
                          "  clear: both;"
                          "}"
                          /* Responsive layout - when the screen is less than 600px wide, make the two columns stack on top of each other instead of next to each other */
                          "@media screen and (max-width: 481px) {"
                          "  .col-25, .col-75, input[type=submit] {"
                          "    width: 100%;"
                          "    margin-top: 0;"
                          "  }"
                          "}"
                          "</style>"
                          "</head>"
                          "<body>"
                          "<ul>"
                          "  <li><a class=\"active\" href=\"?home\">Connections</a></li>"
                          "  <li><a href=\"?contact\">Contact</a></li>"
                          "  <li><a href=\"?about\">About</a></li> "
                          " <li style=\"float:right\"><a href=\"?about\"> <img src=\"logo2.png\" width=\"70\" height=\"14\" /></a></li>"
                          "</ul>"
                          "<div style=\"padding:20px;margin-top:50px;\" class=\"container\">"
                          "  <form action=\"/index_html\">"
                          "<h2>Wi-Fi Configuration</h2>"
                          "<p>This part is used to change the network that gateway will connect. Select the right SSID from drop-down selections and write password for this network. </p>"
                          "  <div class=\"row\">"
                          "    <div class=\"col-25\">"
                          "      <label for=\"ssid\">SSID</label>"
                          "    </div>"
                          "    <div class=\"col-15\">"
                          "      <select id=\"ssid\" name=\"ssid\">",
                          -1);
    for (int i = 0; i < ap_num; i++)
    {
        strcpy(size_ssid, (char *)ap_records[i].ssid);
        httpd_resp_send_chunk(req, "    <option value='", -1);
        httpd_resp_send_chunk(req, (char *)ap_records[i].ssid, strlen(size_ssid));
        httpd_resp_send_chunk(req, "'>", -1);
        httpd_resp_send_chunk(req, (char *)ap_records[i].ssid, strlen(size_ssid));
        httpd_resp_send_chunk(req, " signal level:  ", -1);
        if (ap_records[i].rssi >= -55)
        {
            httpd_resp_send_chunk(req, " 5 ", -1);
        }
        else if (ap_records[i].rssi < -55 && ap_records[i].rssi >= -65)
        {
            httpd_resp_send_chunk(req, " 4 ", -1);
        }
        else if (ap_records[i].rssi < -65 && ap_records[i].rssi >= -75)
        {
            httpd_resp_send_chunk(req, " 3", -1);
        }
        else if (ap_records[i].rssi < -75 && ap_records[i].rssi >= -85)
        {
            httpd_resp_send_chunk(req, " 2 ", -1);
        }
        else if (ap_records[i].rssi < -85)
        {
            httpd_resp_send_chunk(req, " 1", -1);
        }
        else
        {
            httpd_resp_send_chunk(req, " 0", -1);
        }

        httpd_resp_send_chunk(req, "</option>", -1);
    }
    httpd_resp_send_chunk(req,
                          "      </select>"
                          "    </div>"
                          "  </div>"

                          "<div class=\"row\">"
                          "    <div class=\"col-25\">"
                          "      <label for=\"pass\">Password</label>"
                          "    </div>"
                          "    <div class=\"col-15\">"
                          "      <input type=\"text\" id=\"fname\" name=\"pass\" placeholder=\"Your password..\">"
                          "    </div>"
                          "  </div>"
                          "  <br>"
                          "  <div class=\"row\">"
                          "    <input type=\"submit\" value=\"Submit\">"
                          "  </div>"
                          "  </form>"
                          "  Storage:  ",
                          -1);
    httpd_resp_send_chunk(req, ssid_get, strlen(ssid_get));
    httpd_resp_send_chunk(req, "  Pass:  ", -1);
    httpd_resp_send_chunk(req, pass_get, strlen(pass_get));
    httpd_resp_send_chunk(req,
                          "</div>"
                          "<br>"

                          "<div class=\"container\">"
                          "  <form action=\"/index_html\">"

                          "<h2>Connection Type</h2>"
                          "<p>Choose the right option for connection type.</p>"

                          "  <div class=\"row\">"
                          "    <div class=\"col-25\">"
                          "      <label for=\"conn\">Type:</label>"
                          "    </div>"
                          "    <div class=\"col-15\">"
                          "  <select id='connections' name='connections'>"
                          "    <option value='wifi'>wifi</option>"
                          "    <option value='gsm'>Gsm</option>"
                          "    <option value='zigbee'>Zigbee</option>"
                          "  </select>"
                          "    </div>"
                          "  </div>"

                          "  <br>"
                          "  <div class=\"row\">"
                          "    <input type=\"submit\" value=\"Submit\">"
                          "  </div>"
                          "  </form>",
                          -1);
    httpd_resp_send_chunk(req, " Storage:  ", -1);
    httpd_resp_send_chunk(req, conn_get, strlen(conn_get));
    httpd_resp_send_chunk(req, "</div>"

                               "</body>"

                               "</html>",
                          -1);

    return ESP_OK;
}
#define IS_FILE_EXT(_FileName, ext) (strcasecmp(&_FileName[strlen(_FileName) - sizeof(ext) + 1], ext) == 0)
/* Set HTTP response content type according to file extension */
static esp_err_t SetFileContentType(httpd_req_t *req, const char *_FileName) {
  if(IS_FILE_EXT(_FileName, ".pdf")) {
    return httpd_resp_set_type(req, "application/pdf");
  }
  else if(IS_FILE_EXT(_FileName, ".html")) {
    return httpd_resp_set_type(req, "text/html");
  }
  else if(IS_FILE_EXT(_FileName, ".png")) {
    return httpd_resp_set_type(req, "image/png");
  }
  else if(IS_FILE_EXT(_FileName, ".jpeg")) {
    return httpd_resp_set_type(req, "image/jpeg");
  }
  else if(IS_FILE_EXT(_FileName, ".ico")) {
    return httpd_resp_set_type(req, "image/x-icon");
  }
  /* This is a limited set only */
  /* For any other type always set as plain text */
  return httpd_resp_set_type(req, "text/plain");
}
/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
static const char *GetPathFromUri(char *dest, const char *base_path, const char *uri, size_t destsize) {

  const size_t base_pathlen = strlen(base_path);
  size_t       pathlen = strlen(uri);

  const char  *quest = strchr(uri, '?');
  if(quest) {
    pathlen = MIN(pathlen, quest - uri);
  }
  const char *hash = strchr(uri, '#');
  if(hash) {
    pathlen = MIN(pathlen, hash - uri);
  }

  if(base_pathlen + pathlen + 1 > destsize) {
    /* Full path string won't fit into destination buffer */
    return NULL;
  }
  /* Construct full path (base + path) */
  strcpy(dest, base_path);
  strlcpy(dest + base_pathlen, uri, pathlen + 1);

  /* Return pointer to path, skipping the base */
  return dest + base_pathlen;
}
/* Handler to download a file kept on the server */
static esp_err_t webserver_get_handler(httpd_req_t *req) {
  char        filepath[FILE_PATH_MAX];
  FILE       *fd = NULL;
  struct stat file_stat;

  for(int a = 0; a < 5; a++) {
    strcpy(parsed[a], "");
  }
  ESP_LOGI(TAG, " storage ssid: %s     pass: %s   ", ssid_get, pass_get);

  const char *_FileName = GetPathFromUri(filepath, ((struct TFileServerData *)req->user_ctx)->base_path, req->uri, sizeof(filepath));

  printf("uri %s \n", req->uri);
  strcpy(parse, req->uri); // calling strcpy function

  printf("parse %s ,   file name:  %s\n", parse, _FileName);

  if(!_FileName) {
    ESP_LOGE(TAG, "file name is too long");
    /* Respond with 500 Internal Server Error */
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "file name too long");
    return ESP_FAIL;
  }

  /* If name has trailing '/', respond with directory contents */
  if(_FileName[strlen(_FileName) - 1] == '/') {
    return ask_resp_dir_html(req, filepath);
  }
  if(stat(filepath, &file_stat) == -1) {
    /* If file not present on SPIFFS check if URI
     * corresponds to one of the hardcoded paths */
    if(strcmp(_FileName, "/index_html") == 0) {
      ESP_LOGI(TAG, "inside index_html");
      if(!(strcmp(parse, "/index_html"))) {
	      return http_resp_dir_html(req, filepath);
      }
      else
	      return connect_get_handler(req);
    }
    else if(strcmp(_FileName, "/contact") == 0) {
      ESP_LOGI(TAG, "inside contact");
      if(!(strcmp(parse, "/contact"))) {
	      return contact_resp_dir_html(req, filepath);
      }
      else
	      return connect_get_handler(req);
    }
    else if(strcmp(_FileName, "/about") == 0) {
      ESP_LOGI(TAG, "inside contact");
      if(!(strcmp(parse, "/about"))) {
	      return about_resp_dir_html(req, filepath);
      }
      else
	      return connect_get_handler(req);
    }
    else if(strcmp(_FileName, "/WifiNeutral.png") == 0) {
      ESP_LOGI(TAG, "WifiNeutral!");
      return WifiNeutral_get_handler(req);
    }
    else if(strcmp(_FileName, "/WifiLV1.png") == 0) {
      ESP_LOGI(TAG, "WifiLV1!");
      return WifiLV1_get_handler(req);
    }
    else if(strcmp(_FileName, "/WifiLV2.png") == 0) {
      ESP_LOGI(TAG, "WifiLV2!");
      return WifiLV2_get_handler(req);
    }
    else if(strcmp(_FileName, "/WifiLV3.png") == 0) {
      ESP_LOGI(TAG, "WifiLV3!");
      return WifiLV3_get_handler(req);
    }
    else if(strcmp(_FileName, "/WifiLV4.png") == 0) {
      ESP_LOGI(TAG, "WifiLV4!");
      return WifiLV4_get_handler(req);
    }
    ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
    /* Respond with 404 Not Found */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
    return ESP_FAIL;
  }

  fd = fopen(filepath, "r");
  if(!fd) {
    ESP_LOGE(TAG, "Failed to read existing file : %s", filepath);
    /* Respond with 500 Internal Server Error */
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Sending file : %s (%ld bytes)...", _FileName, file_stat.st_size);
  SetFileContentType(req, _FileName);

  /* Retrieve the pointer to scratch buffer for temporary storage */
  char  *chunk = ((struct TFileServerData *)req->user_ctx)->scratch;
  size_t chunksize;
  do {
    /* Read file in chunks into the scratch buffer */
    chunksize = fread(chunk, 1, SCRATCH_BUFSIZE, fd);

    /* Send the buffer contents as HTTP response chunk */
    if(httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {

      fclose(fd);
      ESP_LOGE(TAG, "File sending failed!");
      /* Abort sending file */
      httpd_resp_sendstr_chunk(req, NULL);
      /* Respond with 500 Internal Server Error */
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
      return ESP_FAIL;
    }

    /* Keep looping till the whole file is sent */
  }
  while(chunksize != 0);

  /* Close file after sending complete */
  fclose(fd);
  ESP_LOGI(TAG, "File sending complete");

  /* Respond with an empty chunk to signal HTTP response completion */
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}
esp_err_t StartFileServer(const char *base_path) {
  static struct TFileServerData *ServerData = NULL;
  /* Validate file storage base path */
  if(!base_path || strcmp(base_path, "/spiffs") != 0) {
    ESP_LOGE(TAG, "File server presently supports only '/spiffs' as base path");
    return ESP_ERR_INVALID_ARG;
  }
  if(ServerData) {
    ESP_LOGE(TAG, "File server already started");
    return ESP_ERR_INVALID_STATE;
  }
  /* Allocate memory for server data */
  ServerData = calloc(1, sizeof(struct TFileServerData));
  if(!ServerData) {
    ESP_LOGE(TAG, "Failed to allocate memory for server data");
    return ESP_ERR_NO_MEM;
  }
  strlcpy(ServerData->base_path, base_path, sizeof(ServerData->base_path));

  httpd_handle_t server = NULL;
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();

  /* Use the URI wildcard matching function in order to
   * allow the same handler to respond to multiple different
   * target URIs which match the wildcard scheme */
  config.uri_match_fn = httpd_uri_match_wildcard;

  ESP_LOGI(TAG, "Starting HTTP Server");
  if(httpd_start(&server, &config) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start file server!");
    return ESP_FAIL;
  }

  /* URI handler for getting uploaded files */
  httpd_uri_t FileServer = {
    .uri = "/*", // Match all URIs of type /path/to/file
    .method = HTTP_GET,
    .handler = webserver_get_handler,
    .user_ctx = ServerData // Pass server data as context
  };
  httpd_register_uri_handler(server, &FileServer);

  return ESP_OK;
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

  ESP_ERROR_CHECK(InitSpiffs());
  ESP_ERROR_CHECK(StartFileServer("/spiffs"));
}
