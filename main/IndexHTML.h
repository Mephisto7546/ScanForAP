const char IndexHTML[] = R"=====(
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html lang="en">

<style>
  html{
    display: inline-block; 
    text-align: center;
  }
  body {
    max-width: 70em;
    margin: 0 auto;
    /*border: 20rem;
    padding: 0rem;*/
    font-size: 0.7rem;
  }
  h1{
    color: steelblue;	
  }
  h2{
    color: steelblue;
  }
  p{
    color: darkgray;
    font-size: 0.8rem;
  }
  body{
    Background: rgb(59, 58, 58);
  }
  .title{
    color: rgb(50, 50, 255);
  }
  .StandardTableStyle{
    color: darkgray;
    font-size: 1.0rem;
    vertical-align: top;
    align-items: center;
  }
  .TableEntry{
    color: steelblue;
    font-size: 1.5rem;
  }
  .TableEntryHeader{
    color: steelblue;
    font-size: 2.0rem;
  }
  .TableInventory{
    color: tomato;
    vertical-align: top;
    align-items: center;
    font-family: 'Courier New', Courier, monospace;
    font-size: 1.2rem;
  }
</style>
<head>
    <meta content="width=device-width, initial-scale=1.0, maximum-scale=2.0, minimum-scale=1.0, user-scalable=no" name="viewport" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
        body {
            background-color: lightblue;
        }
        
        h1 {
            font-size: 2.0em;
            color: red;
        }
    </style>
</head>

<body>
    <h1>Chose Wifi and type in credentials</h1>
    <br>
    <br>
    <br>
    <br>
    <form action="/action_page.php">
      <label for="cars">Choose a car:</label>
      <select name="cars" id="cars">
        <option value="volvo">Volvo</option>
        <option value="saab">Saab</option>
        <option value="opel">Opel</option>
        <option value="audi">Audi</option>
      </select>
      <br><br>
      <input type="chose" value="Submit">
    </form>
</body>

</html>
)=====";