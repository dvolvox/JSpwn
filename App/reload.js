function reload() {
var redir = location.hash.split("#")[1];
if (redir){
x = document.getElementsByTagName('iframe');
x[0].setAttribute('src',redir);
}}