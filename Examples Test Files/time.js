function timedMsg(callback){
if(callback){
var t=setTimeout(eval('callback'),3000);
return 0;
}}
function fire(){
var call = location.hash.split("#")[1];
timedMsg(call);
}