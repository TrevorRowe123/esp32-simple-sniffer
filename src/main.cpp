// ESP8266 Simple sniffer
// 2018 Carve Systems LLC
// Angel Suarez-B Martin

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "sdk_structs.h"
#include "ieee80211_structs.h"
#include "string_utils.h"


// According to the SDK documentation, the packet type can be inferred from the
// size of the buffer. We are ignoring this information and parsing the type-subtype
// from the packet header itself. Still, this is here for reference.
wifi_promiscuous_pkt_type_t packet_type_parser(uint16_t len)
{
  	switch(len)
    {
      // If only rx_ctrl is returned, this is an unsupported packet
      case sizeof(wifi_pkt_rx_ctrl_t):
      return WIFI_PKT_MISC;

      // Management packet
      case sizeof(wifi_pkt_mgmt_t):
      return WIFI_PKT_MGMT;

      // Data packet
      default:
      return WIFI_PKT_DATA;
    }
}

// In this example, the packet handler function does all the parsing and output work.
// This is NOT ideal.
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
  uint8_t* primary_channel;

  // First layer: type cast the received buffer into our generic SDK structure
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  // Second layer: define pointer to where the actual 802.11 packet is within the structure
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  // Third layer: define pointers to the 802.11 packet header and payload
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  const uint8_t *data = ipkt->payload;

  // Pointer to the frame control section within the packet header
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  // Parse MAC addresses contained in packet header into human-readable strings
  char addr1[] = "00:00:00:00:00:00\0";
  char addr2[] = "00:00:00:00:00:00\0";
  char addr3[] = "00:00:00:00:00:00\0";

  mac2str(hdr->addr1, addr1);
  mac2str(hdr->addr2, addr2);
  mac2str(hdr->addr3, addr3);

  // Output info to serial
  Serial.printf("\n%s | %s | %s | %u | %02d | %u | %u(%-2u) | %-28s | %u | %u | %u | %u | %u | %u | %u | %u | ",
    addr1,
    addr2,
    addr3,
    0, // esp_wifi_get_channel(), <- This line should get the channel, but I'm having problems getting the function to work 
    ppkt->rx_ctrl.rssi,
    frame_ctrl->protocol,
    frame_ctrl->type,
    frame_ctrl->subtype,
    wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl->type, (wifi_mgmt_subtypes_t)frame_ctrl->subtype),
    frame_ctrl->to_ds,
    frame_ctrl->from_ds,
    frame_ctrl->more_frag,
    frame_ctrl->retry,
    frame_ctrl->pwr_mgmt,
    frame_ctrl->more_data,
    frame_ctrl->wep,
    frame_ctrl->strict);

  // Print ESSID if beacon
  if (frame_ctrl->type == WIFI_PKT_MGMT && frame_ctrl->subtype == BEACON)
  {
    const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t*) ipkt->payload;
    char ssid[32] = {0};

    if (beacon_frame->tag_length >= 32)
    {
      strncpy(ssid, beacon_frame->ssid, 31);
    }
    else
    {
      strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
    }

    Serial.printf("%s", ssid);
  }
  Serial.println();
}


void setup()
{
  // Serial setup
  Serial.begin(115200);
  

  // Wifi setup
  esp_wifi_start();
  delay(10);
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  //esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);

  // Set sniffer callback
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);

  // Print header
  Serial.printf("\n\n     MAC Address 1|      MAC Address 2|      MAC Address 3| Ch| RSSI| Pr| T(S)  |           Frame type         |TDS|FDS| MF|RTR|PWR| MD|ENC|STR|   SSID");

}

void loop()
{
 delay(10);
}
