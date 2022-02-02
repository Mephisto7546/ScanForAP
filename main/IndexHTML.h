const char IndexHTML[] = R"=====(
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html lang="en">

  <style>
    * {
      box-sizing: border-box;
    }
    body{
      margin: auto;
      background-color: #4c4c4c;
    }
    @media screen and (min-width: 851px) {
      div.navbar{
        height: 17vh;
      }
      div.navtitle {
        font-size: 70px;
        height: 20px;
        line-height: 15vh;
      }
      div.navheading{
        font-size: 1.1em;
        left: 65%;
      }
      div.navdata{
        font-size: 1.1em;
        left: 72%;
      }
      .conMid{
        padding-top: 16vh;
      }
      div.tabcolheader{
        font-size: 1.5em;
      } 
      .bdtBtnAlign{
        width: 25vh;
      }
    }
    @media screen and (max-width: 850px) {
      div.navbar{
        height: 20vh;
      }
      div.navtitle {
        font-size: 50px;
        height: 20px;
        line-height: 15vh;
      }
      div.navheading{
        font-size: 0.80em;
        left: 65%;
      }
      div.navdata{
        font-size: 0.80em;
        left: 70%;
      }
      .conMid{
        padding-top: 18vh;
      }
      div.tabcolheader{
        font-size: 1.3em;
      } 
      .bdtBtnAlign{
        width: 20vh;
      }
    }
    @media screen and (max-width: 580px) {
      div.navbar{
        height: 7vh;
      }
      div.navtitle {
        font-size: 30px;
        height: 40px;
        line-height: 6vh;
      }
      div.navheading{
        font-size: 0.7em;
        left: 65%;
      }
      div.navdata{
        font-size: 0.7em;
        left: 75%;
      }
      .conMid{
        padding-top: 7vh;
      }
      div.tabcolheader{
        font-size: 0.8em;
      } 
      .bdtBtnAlign{
        width: 10vh;
      }
    }
    .navbar {
      width: 100%;
      margin: 0px;
      padding: 5px 0px;
      background-color: rgb(95, 95, 95);
      color: #000000;
      border-bottom: 5px solid #293578;
    }
    .fixed-top {
      position: fixed;
      top: 0;
      right: 0;
      left: 0;
      z-index: 1030;
    }
    
    .navtitle {
      float: left;
      height: 20px;
      font-family: "Consolas", "Arial", sans-serif;
      font-weight: bold;
    }
   .navheading {
     position: fixed;
     float: right;
     height: 50px;
     font-family: "Verdana", "Arial", sans-serif;
     font-weight: bold;
     line-height: 40px;
     padding-right: 20px;
   }
   .navdata {
      justify-content: flex-end;
      position: fixed;
      height: 50px;
      font-family: "Verdana", "Arial", sans-serif;
      font-weight: bold;
      line-height: 40px;
      padding-right: 20px;
   }
   table {
      width:100%;
      border-spacing: 0px;
    }
    tr {
      border: 1px solid white;
      font-family: "Verdana", "Arial", sans-serif;
    }
    th {
      height: 20px;
      padding: 3px 15px;
      background-color: #343a40;
      color: #FFFFFF !important;
      }
    td {
      height: 20px;
      padding: 3px 15px;
    }
    .TabCol1{
      background-color:rgb(200,200,200); 
      width: 20%; 
      color:#000000 ;
    }
    .TabCol2{
      background-color:rgb(0,0,0); 
      color:#FFFFFF;
    }
    .tabledata {
      font-size: 2em;
      position: relative;
      padding-left: 5px;
      padding-top: 5px;
      height:   25px;
      border-radius: 5px;
      color: #FFFFFF;
      line-height: 20px;
      transition: all 200ms ease-in-out;
      background-color: #00AA00;
    }
    .buttongroup{
      text-align: center;
    }
    .fanrpmslider {
      width: 50%;
      height: 55px;
      outline: none;
      height: 25px;
      margin: auto;
      display: block;
      margin: auto;
    }
    .textfanslider{
      font-family: "Verdana", "Arial", sans-serif;
      font-size: 1em;
      text-align: center;
      border-radius: 5px;
    }
    .bodytext {
      font-family: "Verdana", "Arial", sans-serif;
      font-size: 1em;
      text-align: left;
      border-radius: 5px;
      display: inline-block;
      margin-left: 2vw;
    }
    .category {
      font-family: "Consolas", "Arial", sans-serif;
      font-weight: bold;
      font-size: 2em;
      text-align: center;
      line-height: 50px;
      margin-left: 12px;
      color: #000000;
    }
    .heading {
      font-family: "Verdana", "Arial", sans-serif;
      font-weight: normal;
      font-size: 1em;
      text-align: left;
    }
    #btn0{
      background-color: #fd3636;      
    }
    #btn1{
      background-color: #44b900;      
    }
    #btn2{
      background-color: #0f0099;      
    }
    #btn3{
      background-color: #e4e000;      
    }
    .btn {
      background-color: #444444;
      border: 2px solid #666666;
      border-radius: 30px;
      box-shadow: 5px 5px 2px 0px #000;
      color: whitesmoke;
      padding: 10px 5px;
      width: 80px;
      text-align: center;
      text-decoration: none;
      display: inline;
      font-size: 0.7em;
      margin: 4px 2px;
      cursor: pointer;

      @media(min-width: 600px) {
        margin: 0 1em 2em;
      }
      &:hover { text-decoration: none; }
    }
    .btn-5 {
      border: 0 solid;
      /* box-shadow: inset 0 0 20px rgba(255, 255, 255, 0); */
      outline: 1px solid;
      outline-color: rgba(255, 255, 255, .5);
      outline-offset: 0px;
      text-shadow: none;
      transition: all 1250ms cubic-bezier(0.19, 1, 0.22, 1);
    } 
    .btn-5:hover {
      border: 1px solid;
      /* box-shadow: inset 0 0 20px rgba(255, 255, 255, .5), 0 0 20px rgba(255, 255, 255, .2); */
      outline-color: rgba(255, 255, 255, 0);
      outline-offset: 15px;
      text-shadow: 1px 1px 2px #427388; 
    }

    .foot {
      font-family: "Verdana", "Arial", sans-serif;
      font-size: 2em;
      position: relative;
      height:   30px;
      text-align: center;   
      color: #AAAAAA;
      line-height: 20px;
    }
    .conTop{
      margin: auto;
      max-width: 50vw;
    }
    .conLow{
      margin: auto;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
    }
    table tr:first-child th:first-child {
      border-top-left-radius: 5px;
    }
    table tr:first-child th:last-child {
      border-top-right-radius: 5px;
    }
    table tr:last-child td:first-child {
      border-bottom-left-radius: 5px;
    }
    table tr:last-child td:last-child {
      border-bottom-right-radius: 5px;
    }
  </style>

  <head>
    <meta content="width=device-width, initial-scale=1.0, maximum-scale=2.0, minimum-scale=0.5, user-scalable=no"
      name="viewport" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <div class="navbar fixed-top">
      <div class="container conTop">
        <div class="navtitle">Sensor Monitor</div>
        <div class="navdata" id="date">mm/dd/yyyy</div>
        <div class="navheading">DATE</div><br>
        <div class="navdata" id="time">00:00:00</div>
        <div class="navheading">TIME</div>

      </div>
    </div>
  </head>
  <main class="container conMid">
    <div class="category">Sensor Readings</div>
    <div>
      <table>
        <colgroup>
          <col span="1" class="TabCol1">
          <col span="1" class="TabCol1">
          <col span="1" class="TabCol1">
        </colgroup>
        <col span="2" class="TabCol2">
        <col span="2" class="TabCol2">
        <col span="2" class="TabCol2">
        <tr>
          <th colspan="1">
            <div class="heading">Pin</div>
          </th>
          <th colspan="1">
            <div class="heading">Bits</div>
          </th>
          <th colspan="1">
            <div class="heading">Volts</div>
          </th>
        </tr>
        <tr>
          <td>
            <div class="tabcolheader">Analog pin 34</div>
          </td>
          <td>
            <div class="tabledata" id="b0"></div>
          </td>
          <td>
            <div class="tabledata" id="v0"></div>
          </td>
        </tr>
        <tr>
          <td>
            <div class="tabcolheader">Analog pin 35</div>
          </td>
          <td>
            <div class="tabledata" id="b1"></div>
          </td>
          <td>
            <div class="tabledata" id="v1"></div>
          </td>
        </tr>
        <tr>
          <td>
            <div class="tabcolheader">Digital switch</div>
          </td>
          <td colspan="2">
            <div class="tabledata" id="switch"></div>
          </td>
        </tr>
      </table>
    </div>
    <br>
    <div class="category">Sensor Controls</div>
    <br>
    <div class="buttongroup">
      <!-- <div class="bodytext bdtBtnAlign">LED red </div> -->
        <button type="button" class="btn btn-5" id="btn0" onclick="ButtonPress0()">Led  red</button>
      <!-- </div> -->
      <!-- <div class="bodytext bdtBtnAlign">LED green </div> -->
        <button type="button" class="btn btn-5" id="btn1" onclick="ButtonPress0()">Led green</button>
      <!-- </div> -->
      <!-- <div class="bodytext bdtBtnAlign">LED blue </div> -->
        <button type="button" class="btn btn-5" id="btn2" onclick="ButtonPress0()">led  blue</button>
      <!-- </div> -->
      <!-- <div class="bodytext bdtBtnAlign">LED yellow </div> -->
        <button type="button" class="btn btn-5" id="btn3" onclick="ButtonPress0()">Led yellow</button>
      <!-- </div> -->
      <!-- <br>
      <div class="bodytext  bdtBtnAlign" >Switch</div>
      <button type="button" class="btn" id="btn1" onclick="ButtonPress1()">Toggle</button>
      </div> -->
    </div>
    <br>
    <br>
    <div class="textfanslider">Fan Speed Control (RPM: <span id="fanrpm"></span>)</div>
    <br>
    <input type="range" class="fanrpmslider" min="0" max="255" value="0" width="0%"
      oninput="UpdateSlider(this.value)" />
    <br>
    <br>
  </main>
  <script type = "text/javascript">
  
    // global variable visible to all java functions
    var xmlHttp=createXmlHttpObject();
    // function to create XML object
    function createXmlHttpObject(){
      if(window.XMLHttpRequest){
        xmlHttp=new XMLHttpRequest();
      }
      else{
        xmlHttp=new ActiveXObject("Microsoft.XMLHTTP");
      }
      return xmlHttp;
    }
    // function to handle button press from HTML code above
    // and send a processing string back to server
    // this processing string is used in the .on method
    function ButtonPress0() {
      var xhttp = new XMLHttpRequest(); 
      var message;
      // if you want to handle an immediate reply (like status from the ESP
      // handling of the button press use this code
      // since this button status from the ESP is in the main XML code
      // we don't need this
      // remember that if you want immediate processing feedbac you must send it
      // in the ESP handling function and here
      /*
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          message = this.responseText;
          // update some HTML data
        }
      }
      */
       
      xhttp.open("PUT", "BUTTON_0", false);
      xhttp.send();
    }
    // function to handle button press from HTML code above
    // and send a processing string back to server
    // this processing string is use in the .on method
    function ButtonPress1() {
      var xhttp = new XMLHttpRequest(); 
      /*
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          document.getElementById("button1").innerHTML = this.responseText;
        }
      }
      */
      xhttp.open("PUT", "BUTTON_1", false);
      xhttp.send(); 
    }
    
    function UpdateSlider(value) {
      var xhttp = new XMLHttpRequest();
      // this time i want immediate feedback to the fan speed
      // yea yea yea i realize i'm computing fan speed but the point
      // is how to give immediate feedback
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          // update the web based on reply from  ESP
          document.getElementById("fanrpm").innerHTML=this.responseText;
        }
      }
      // this syntax is really weird the ? is a delimiter
      // first arg UPDATE_SLIDER is use in the .on method
      // server.on("/UPDATE_SLIDER", UpdateSlider);
      // then the second arg VALUE is use in the processing function
      // String t_state = server.arg("VALUE");
      // then + the controls value property
      xhttp.open("PUT", "UPDATE_SLIDER?VALUE="+value, true);
      xhttp.send();
    }
    // function to handle the response from the ESP
    function response(){
      var message;
      var barwidth;
      var currentsensor;
      var xmlResponse;
      var xmldoc;
      var dt = new Date();
      var color = "#e8e8e8";
     
      // get the xml stream
      xmlResponse=xmlHttp.responseXML;
  
      // get host date and time
      document.getElementById("time").innerHTML = dt.toLocaleTimeString();
      document.getElementById("date").innerHTML = dt.toLocaleDateString();
  
      // A0
      xmldoc = xmlResponse.getElementsByTagName("B0"); //bits for A0
      message = xmldoc[0].firstChild.nodeValue;
      
      if (message > 2048){
        color = "#aa0000";
      }
      else {
        color = "#0000aa";
      }
      
      barwidth = message / 40.95;
      document.getElementById("b0").innerHTML=message;
      document.getElementById("b0").style.width=(barwidth+"%");
      // if you want to use global color set above in <style> section
      // other wise uncomment and let the value dictate the color
      //document.getElementById("b0").style.backgroundColor=color;
      //document.getElementById("b0").style.borderRadius="5px";
      
      xmldoc = xmlResponse.getElementsByTagName("V0"); //volts for A0
      message = xmldoc[0].firstChild.nodeValue;
      document.getElementById("v0").innerHTML=message;
      document.getElementById("v0").style.width=(barwidth+"%");
      // you can set color dynamically, maybe blue below a value, red above
      document.getElementById("v0").style.backgroundColor=color;
      //document.getElementById("v0").style.borderRadius="5px";
  
      // A1
      xmldoc = xmlResponse.getElementsByTagName("B1");
      message = xmldoc[0].firstChild.nodeValue;
      if (message > 2048){
        color = "#aa0000";
      }
      else {
        color = "#0000aa";
      }
      document.getElementById("b1").innerHTML=message;
      width = message / 40.95;
      document.getElementById("b1").style.width=(width+"%");
      document.getElementById("b1").style.backgroundColor=color;
      //document.getElementById("b1").style.borderRadius="5px";
      
      xmldoc = xmlResponse.getElementsByTagName("V1");
      message = xmldoc[0].firstChild.nodeValue;
      document.getElementById("v1").innerHTML=message;
      document.getElementById("v1").style.width=(width+"%");
      document.getElementById("v1").style.backgroundColor=color;
      //document.getElementById("v1").style.borderRadius="5px";
  
      xmldoc = xmlResponse.getElementsByTagName("LED");
      message = xmldoc[0].firstChild.nodeValue;
  
      if (message == 0){
        document.getElementById("btn0").innerHTML="Turn ON";
      }
      else{
        document.getElementById("btn0").innerHTML="Turn OFF";
      }
         
      xmldoc = xmlResponse.getElementsByTagName("SWITCH");
      message = xmldoc[0].firstChild.nodeValue;
      document.getElementById("switch").style.backgroundColor="rgb(200,200,200)";
      // update the text in the table
      if (message == 0){
        document.getElementById("switch").innerHTML="Switch is OFF";
        document.getElementById("btn1").innerHTML="Turn ON";
        document.getElementById("switch").style.color="#0000AA"; 
      }
      else {
        document.getElementById("switch").innerHTML="Switch is ON";
        document.getElementById("btn1").innerHTML="Turn OFF";
        document.getElementById("switch").style.color="#00AA00";
      }
     }
  
    // general processing code for the web page to ask for an XML steam
    // this is actually why you need to keep sending data to the page to 
    // force this call with stuff like this
    // server.on("/xml", SendXML);
    // otherwise the page will not request XML from the ESP, and updates will not happen
    function process(){
     
     if(xmlHttp.readyState==0 || xmlHttp.readyState==4) {
        xmlHttp.open("PUT","xml",true);
        xmlHttp.onreadystatechange=response;
        xmlHttp.send(null);
      }       
        // you may have to play with this value, big pages need more porcessing time, and hence
        // a longer timeout
        setTimeout("process()",100);
    }
  
  
  </script>
  
</html>
)=====";