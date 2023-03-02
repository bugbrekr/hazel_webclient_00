let socket = null
send_over_socket = false
global_exit_callback = null
login_authorized = false

function hash_sha256(string) {
  const utf8 = new TextEncoder().encode(string);
  return crypto.subtle.digest('SHA-256', utf8).then((hashBuffer) => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((bytes) => bytes.toString(16).padStart(2, '0'))
      .join('');
    return hashHex;
  });
}

function ws_auth(username, password, callbackSuccess, callbackFailure){
  return new Promise((callbackSuccess, callbackFailure)=>{
    socket.once("auth", (data)=>{
      if (data['success'] == true){
        callbackSuccess(data["splash_text"])
      } else if (data['success'] == false){
        callbackFailure()
      }
    })
    hash_sha256(password).then((password)=>{
      socket.emit("auth", {"username": username, "password": password})
    })
  })
}

class TerminalCommands {
  constructor() {
    let terminalunit = this
    socket = io("wss://");
    socket.on("terminal", (data)=>{
      if (data["type"] == "control"){
        if (data["command"] == "exit"){
          global_exit_callback()
        } else if (data["command"] == "enter_callback"){
          let pwd_mode = false
          if (data["pwd_mode"] == true){
            pwd_mode = true
          }
          get_input_text(pwd_mode).then(function (text){
            socket.emit("terminal", {"type": "enter_callback", "text": text})
          })
        }
      } else if (data["type"] == "stdout"){
        terminalunit.print(data["stdout"], "")
      } else if (data["type"] == "js-exec"){
        eval(data["js-command"])
      }
    })
    socket.on("auth", (data)=>{
      if (data["auto_auth"] == true){
        if (data['success'] == true){
          terminalunit.print("\\n"+data["message"])
          login_authorized = true
          on_command_function("")
        } else if (data['success'] == false){
          terminalunit.print("\\n"+data["message"])
          setTimeout(()=>{
            on_command_function = null
            socket.disconnect()
            socket.destroy()
            terminalunit.print("Socket destroyed.")
          }, 500)
        }
      }
    })
  }
  print_html(html){
    $(html).insertBefore("#terminal-prompt")
  }
  format_text(text){
    let html = "<p style='color: white'>"
    let color = ""
    for (let i=0; i<text.length; i++){
      if (text.slice(i, i+2) == "&c"){
        color = text.slice(i+2, i+2+text.slice(i+2).search("&"))
        html += "</p><p style='color: "+color+"'>"
        i+=2+color.length
      } else if (text.slice(i, i+4) == "&ec&") {
          html += "</p><p style='color: white'>"
          i+=3
      } else if (JSON.stringify(text.slice(i, i+2)) == JSON.stringify("\\n")){
         html += "</p><br><p>"
         i+=1
      } else if (text[i] == " ") {
        html += "&nbsp;"
      } else {
        html += text[i]
      }
    }
    // html = html+"</p>"
    html = "<p style='color: white'>"+html+"</p>"
    return html
  }

  print(text, end="\\n"){
    let html = terminalunit.format_text(text)
    html+=terminalunit.format_text(end)
    terminalunit.print_html(html)
  }

  run(exec, args, exit_callback) {
    global_exit_callback = exit_callback
    if (exec == ""){
      exec = exec.trim()
      exit_callback()
      return
    }
    try{
      if (terminalunit[exec+"_command"] == undefined){
        if (send_over_socket==false){
          terminalunit.print(`${exec}: &cred&command not found&ec&`)
          exit_callback()
        } else if (send_over_socket==true){
          socket.emit("terminal", {"type": "command", "exec": exec, "args": args})
        }
      } else{
        terminalunit[exec+"_command"](args, exit_callback)
      }
    } catch (e) {
      setTimeout(exit_callback, 100)
      throw e
    }
  }

  test_command(args, exit_callback) {
    terminalunit.print("Text:", " ")
    get_input_text().then(function (text){
      terminalunit.print("You typed: "+text)
      exit_callback()
    })
  }

  exit_command(args, exit_callback){
    socket.disconnect()
    socket.destroy()
    terminalunit.print("\nSocket disconnected.")
  }
  logout_command(args, exit_callback){
    socket.disconnect()
    socket.destroy()
    terminalunit.print("\nSocket disconnected.")
  }

  hazel_command(args, exit_callback){
    if (args[0] == "login"){
      terminalunit.print("Username:", " ")
      get_input_text().then(function (username){
        if (login_authorized == true){
          ws_auth(username).then((splash_text)=>{
            window.username = username
            terminalunit.print("Successfully authenticated!\\n")
            terminalunit.print(`Logged in as ${username}.`)
            send_over_socket = true
            exit_callback()
          }, ()=>{
            terminalunit.print("Authentication failed.")
            send_over_socket = false
            exit_callback()
          })
        } else {
          terminalunit.print("Password:", " ")
          get_input_text(true).then(function (password){
            ws_auth(username, password).then((splash_text)=>{
              window.username = username
              terminalunit.print("Successfully authenticated!")
              terminalunit.print(`Logged in as ${username}.\\n`)
              terminalunit.print(splash_text)
              send_over_socket = true
              exit_callback()
            }, ()=>{
              terminalunit.print("Authentication failed.")
              send_over_socket = false
              exit_callback()
            })
          })
        }
      })
    }
    else {
      terminalunit.print(`hazel: '${args[0]}' is not a hazel command.`)
      exit_callback()
    }
  }
}
