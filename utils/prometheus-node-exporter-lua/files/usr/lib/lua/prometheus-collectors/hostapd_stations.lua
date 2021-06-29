local ubus = require "ubus"
local bit32 = require "bit32"

local function get_wifi_interface_labels()
  local u = ubus.connect()
  local status = u:call("network.wireless", "status", {})
  local interfaces = {}

  for _, dev_table in pairs(status) do
    for _, intf in ipairs(dev_table['interfaces']) do
      local cfg = intf['config']

      -- Migrate this to ubus interface once it exposes all interesting labels
      local handle = io.popen("hostapd_cli -i " .. cfg['ifname'] .." status")
      local hostapd_status = handle:read("*a")
      handle:close()

      local hostapd = {}
      for line in hostapd_status:gmatch("[^\r\n]+") do
        local name, value = string.match(line, "(.+)=(.+)")
        if name == "phy" then
          hostapd["vif"] = value
        elseif name == "freq" then
          hostapd["freq"] = value
        elseif name == "channel" then
          hostapd["channel"] = value
        elseif name == "bssid[0]" then
          hostapd["bssid"] = value
        elseif name == "ssid[0]" then
          hostapd["ssid"] = value
        end
      end

      local labels = {
        vif = hostapd['vif'],
        ssid = hostapd['ssid'],
        bssid = hostapd['bssid'],
        encryption = cfg['encryption'], -- In a mixed scenario it would be good to know if A or B was used
        frequency = hostapd['freq'],
        channel = hostapd['channel'],
      }

      table.insert(interfaces, labels)
    end
  end

  return interfaces
end

local function scrape()
  local metric_hostapd_station_rx_packets = metric("hostapd_station_receive_packets_total", "counter")
  local metric_hostapd_station_rx_bytes = metric("hostapd_station_receive_bytes_total", "counter")
  local metric_hostapd_station_tx_packets = metric("hostapd_station_transmit_packets_total", "counter")
  local metric_hostapd_station_tx_bytes = metric("hostapd_station_transmit_bytes_total", "counter")

  local metric_hostapd_station_signal = metric("hostapd_station_signal_dbm", "gauge")
  local metric_hostapd_station_connected_time = metric("hostapd_station_connected_seconds_total", "counter")
  local metric_hostapd_station_inactive_msec = metric("hostapd_station_inactive_seconds", "gauge")
  local metric_hostapd_station_flags = metric("hostapd_station_flags", "gauge")

  local metric_hostapd_station_sae_group = metric("hostapd_station_sae_group", "gauge")

  local metric_hostapd_station_vht_capb_su_beamformee = metric("hostapd_station_vht_capb_su_beamformee", "gauge")
  local metric_hostapd_station_vht_capb_mu_beamformee = metric("hostapd_station_vht_capb_mu_beamformee", "gauge")

  local function evaluate_metrics(labels, kv)
    values = {}
    for k, v in pairs(kv) do
      values[k] = v
    end

    -- check if values exist, they may not due to race conditions while querying
    if values["flags"] then
      local flags = {}
      for flag in string.gmatch(values["flags"], "%u+") do
        flags[flag] = true
      end

      labels.flag = "VHT"
      metric_hostapd_station_flags(labels, flags["VHT"] ~= nil and 1 or 0)

      labels.flag = "HT"
      metric_hostapd_station_flags(labels, flags["HT"] ~= nil and 1 or 0)

      labels.flag = "WMM"
      metric_hostapd_station_flags(labels, flags["WMM"] ~= nil and 1 or 0)

      labels.flag = "MFP"
      metric_hostapd_station_flags(labels, flags["MFP"] ~= nil and 1 or 0)

      labels.flag = nil
    end

    -- these metrics can reasonably default to zero, when missing
    metric_hostapd_station_rx_packets(labels, values["rx_packets"] or 0)
    metric_hostapd_station_rx_bytes(labels, values["rx_bytes"] or 0)
    metric_hostapd_station_tx_packets(labels, values["tx_packets"] or 0)
    metric_hostapd_station_tx_bytes(labels, values["tx_bytes"] or 0)

    -- and these metrics can't be defaulted, so check again
    if values["inactive_msec"] ~= nil then
      metric_hostapd_station_inactive_msec(labels, values["inactive_msec"] / 1000)
    end

    if values["signal"] ~= nil then
      metric_hostapd_station_signal(labels, values["signal"])
    end

    if values["connected_time"] ~= nil then
      metric_hostapd_station_connected_time(labels, values["connected_time"])
    end

    if values["vht_caps_info"] ~= nil then
      local caps = tonumber(string.gsub(values["vht_caps_info"], "0x", ""), 16)
      metric_hostapd_station_vht_capb_su_beamformee(labels, bit32.band(bit32.lshift(1, 12), caps) > 0 and 1 or 0)
	    metric_hostapd_station_vht_capb_mu_beamformee(labels, bit32.band(bit32.lshift(1, 20), caps) > 0 and 1 or 0)
    else
      metric_hostapd_station_vht_capb_su_beamformee(labels, 0)
	    metric_hostapd_station_vht_capb_mu_beamformee(labels, 0)
    end

    if values["sae_group"] ~= nil then
      metric_hostapd_station_sae_group(labels, values["sae_group"])
    end
  end

  for _, labels in ipairs(get_wifi_interface_labels()) do
    local vif = labels['vif']
    local handle = io.popen("hostapd_cli -i " .. vif .." all_sta")
    local all_sta = handle:read("*a")
    handle:close()

    local current_station = nil
    local current_station_values = {}

    for line in all_sta:gmatch("[^\r\n]+") do
      if string.match(line, "^%x[0123456789aAbBcCdDeE]:%x%x:%x%x:%x%x:%x%x:%x%x$") then
        if current_station ~= nil then
          labels.station = current_station
          evaluate_metrics(labels, current_station_values)
        end
        current_station = line
        current_station_values = {}
      else
        local name, value = string.match(line, "(.+)=(.+)")
        if name ~= nil then
          current_station_values[name] = value
        end
      end
    end
    labels.station = current_station
    evaluate_metrics(labels, current_station_values)
  end
end

return { scrape = scrape }
