const char CredentialsHTML[] = R"=====(
<!DOCTYPE html>
<html>
  <head>
  <style>
  form {display: grid;padding: 1em; background: #f9f9f9; border: 1px solid #c1c1c1; margin: 2rem auto 0 auto; max-width: 400px; padding: 1em;}}
  form input {background: #fff;border: 1px solid #9c9c9c;}
  form button {background: lightgrey; padding: 0.7em;width: 100%; border: 0;
  label {padding: 0.5em 0.5em 0.5em 0;}
  input {padding: 0.7em;margin-bottom: 0.5rem;}
  input:focus {outline: 10px solid gold;}
  @media (min-width: 300px) {form {grid-template-columns: 200px 1fr; grid-gap: 16px;} label { text-align: right; grid-column: 1 / 2; } input, button { grid-column: 2 / 3; }}
  </style>
  </head>

  <body>
  <form class="form1" id="loginForm" action="">

  <label for="SSID">WiFi Name</label>
  <input id="ssid" type="text" name="ssid" maxlength="64" minlength="4">

  <label for="Password">Password</label>
  <input id="pwd" type="password" name="pwd" maxlength="64" minlength="4">

  <button>Submit</button>
  </form>

  <script>
    document.getElementById(\"loginForm\").addEventListener(\"submit\", (e) => {e.preventDefault(); 
    const formData = new FormData(e.target); 
    const data = Array.from(formData.entries()).reduce((memo, pair) => ({...memo, [pair[0]]: pair[1],  }), {}); 
    var xhr = new XMLHttpRequest(); 
    xhr.open(\"POST\", \"http://192.168.1.1/connection\", true); 
    xhr.setRequestHeader('Content-Type', 'application/json'); 
    xhr.send(JSON.stringify(data)); document.getElementById(\"output\").innerHTML = JSON.stringify(data);
    });
  </script>
  </body>
</html>
)=====";

  