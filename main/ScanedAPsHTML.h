const char ScanedAPsHTML[] = R"=====(
<!DOCTYPE html>
<html>

<head>
	<meta charset="utf-8">
	<title>RSSI as a function of 5 grade symbol</title>
  <style>
    h1{
      color: rgb(25, 25, 240);
    }
    h2{
      color: rgb(60, 60, 60);
    }
    h4{
      color:rgb(22, 30, 141);
    }
    p{
      color: aliceblue;
    }
    body{
      background-color: rgb(63, 63, 63);
    }
    table, th, td {
      padding: 0;
      /* border: 1px solid gray; */
      border-collapse: collapse;
    }
    .tabletdtop{
      border-top: 2px solid rgb(60, 90, 120);
      border-left: 2px solid rgb(60, 90, 120);
      border-right: 2px solid rgb(60, 90, 120);
    }
    .tabletdbot{
      color: aliceblue;
      border-left: 2px solid rgb(60, 90, 120);
      border-right: 2px solid rgb(60, 90, 120);
      border-bottom: 2px solid rgb(60, 90, 120);
    }
    .tablessid{
      border: 2px solid rgb(60, 90, 120);
      /* background-color: steelblue; */
    }
    .APScanList{
      margin: 5;
      margin-left: auto;
      margin-right: auto;
      text-align:center;
      width: 50%;
    }
    .buttonstyle{
      display: inline;
      margin-left: 25%;
      border-radius: 3px;
      /* margin-left: auto; */
      /* margin-right: auto; */
    }
  </style>
</head>

<body>
  <Table class="APScanList">
    <tr>
      <th colspan="3"><h1>Detected APs</h1></th>
    </tr> 
    <tr>
      <th class="tablessid" id="channel1" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td class="tablessid" id="ssid1" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="../WifiNeutral.png" id="rssi1" width=30px></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue1">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel2" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td class="tablessid" id="ssid2" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="../WifiNeutral.png" id="rssi2" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue2">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel3" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid3" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi3" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue3">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel4" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid4" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi4" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue4">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel5" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid5" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi5" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue5">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel6" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid6" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi6" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue06">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel7" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid7" rowspan="2" style="width:60% "><p>SSID</p></th>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi7" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue7">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel8" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid8" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi08" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue8">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel9" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid9" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi9" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue9">RSSI</td>
    </tr> 
    <tr>
      <th class="tablessid" id="channel10" rowspan="2" style="width:20%"><p>CHANNEL</p></th>
      <td  class="tablessid" id="ssid10" rowspan="2" style="width:60% "><p>SSID</p></td>
      <td class="tabletdtop"><img src="/WifiNeutral.png" id="rssi10" width=30px height=20px"></img></td>
    </tr>
    <tr>
      <td class="tabletdbot" id="rssivalue10">RSSI</td>
    </tr>
  </Table>
  <br>
  <br>
  <br>
  <div class="buttonstyle"><button style="width: 50%;" type="button" onclick="getScanResult()"><h2>Scan APs</h2></button></div>
</body>
<script>
  function getScanResult(){

    var xhr = new XMLHttpRequest();
    xhr.open("GET", "ScanedAPsList", true);

    const ImageArray=["/WifiNeutral.png", "/WifiLV1.png", "/WifiLV2.png", "/WifiLV3.png", "/WifiLV4.png", "/WifiLV5.png", "/WifiLV6.png", "/WifiLV7.png"];
    let NumberOfAPs = 0;

    xhr.onload = function(){
      if(xhr.readyState == 4 && xhr.status == 200){
        if(xhr.responseText){
          var data = JSON.parse(xhr.responseText);
          
          NumberOfAPs = data.NumberOfAPs;
          for(let i=0; i<20; i++){
            document.getElementById("ssid"+i.toString).innerHTML = data.APs[i].ssid;

            if(data.APs[i].rssi < -90){
              document.getElementById("rssi"+i.toString).src = ImageArray[0];
            }
            else if(data.APs[i].rssi > -40){
              document.getElementById("rssi"+i.toString).src = ImageArray[4];
            }
            else if(data.APs[i].rssi > -60){
              document.getElementById("rssi"+i.toString).src = ImageArray[3];
            }
            else if(data.APs[i].rssi > -70){
              document.getElementById("rssi"+i.toString).scc = ImageArray[2];
            }
            else if(data.APs[i].rssi > -60){
               document.getElementById("rssi"+i.toString).src = ImageArray[1];
            }

            document.getElementById("rssivalue"+i.toString).innerHTML = data.APs[i].rssi;
          }
        }
        else{
          //failed to parse json
        }
      }
      else{

      }
    };
    xhr.send();
  
    // setTimeout(function() {getScanResult()}, 200);
  }
</script>
</html>
)=====";