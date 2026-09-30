"use strict";
let token="";
try{const raw=location.hash;history.replaceState(null,"",location.pathname);if(raw.startsWith("#token=")){const value=decodeURIComponent(raw.slice(7));if(/^[A-Za-z0-9_-]{10,5500}\.[A-Za-z0-9_-]{86}$/.test(value))token=value;}}catch{}
const state=document.getElementById("activation-state");
if(!token){state.textContent="В ссылке нет корректного персонального ключа. Откройте новую QR-ссылку из Telegram-бота.";}else{state.textContent="Ключ получен. Установите приложение и передайте ключ только своей установке.";const open=document.getElementById("open-windows");open.hidden=false;open.href="chameleon-vpn://activate#token="+encodeURIComponent(token);document.getElementById("copy-token").hidden=false;document.getElementById("show-token").hidden=false;}
document.getElementById("copy-token").onclick=async()=>{try{await navigator.clipboard.writeText(token);state.textContent="Ключ скопирован. Вставьте его в Chameleon и очистите буфер после активации.";}catch{document.getElementById("show-token").click();}};
document.getElementById("show-token").onclick=()=>{document.getElementById("token-value").value=token;document.getElementById("token-box").classList.add("visible");};
window.addEventListener("pagehide",()=>{token="";document.getElementById("token-value").value="";});
