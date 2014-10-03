//SCANJS + JSPRIME TESTE CLI
// file is included here:
var fs = require('fs');

eval(fs.readFileSync(__dirname + '/common/analyzer.js') + '');
eval(fs.readFileSync(__dirname + '/common/engine.js') + '');

var argv = require('optimist').usage('Usage: $node jspwn.js -t [path/to/app] -o [for json output] -c [for custom rules]').demand(['t']).argv;

var results = {};
var dir= argv.t;
var adata=[];
var res = "";
var htmlcontent = "<html><head><title>Output scanner</title></head><body>Data:"+ Date() + "</br><table>";
var time_scan = 0;
var cnt = 0;
var output = "";

//Variaveis do Analyzer
var source = ["URL","documentURI","URLUnencoded","baseURI","cookie","referrer","location", "localStorage.getItem","sessionStorage.getItem","sessionStorage.key","responseText", "window.name", "websockets.onMessage","load","ajax","url.parse", "get", "val","data","value"];
var sink = ["eval","setTimeout","setInterval","execScript","document.write","document.writeln","innerHTML","href","src","html","after","append","appendTo","before","insertAfter","insertBefore","prepend","prependTo","replaceWith","parseHTML","jQuery","globalEval","appendChild","create","insert","setContent","setHTML"];
var user_input = ["location"];

function load_vars(){
	console.log("$ SYSTEM: Reading customized rules");
	var file_read_sinks = fs.readFileSync("custom_sink.txt","utf8");
	var file_read_sinksa = file_read_sinks.split('\n');
	for(var a_sinks = 0; a_sinks < file_read_sinksa.length; a_sinks++)
	{
		sink.push(file_read_sinksa[a_sinks]);
	}
	var file_read_sources = fs.readFileSync("custom_source.txt","utf8");
	var file_read_sourcesa = file_read_sources.split('\n');
	for(var a_sources = 0; a_sources < file_read_sourcesa.length; a_sources++)
	{
		source.push(file_read_sourcesa[a_sources]);
	}
	var file_read_users = fs.readFileSync("custom_userinput.txt","utf8");
	var file_read_usersa = file_read_users.split('\n');
	for(var a_user = 0; a_user < file_read_usersa.length; a_user++)
	{
		user_input.push(file_read_usersa[a_user]);
	}
	
}

//Recursive Function to sumarize all sub folder and files.
function walk(dir) {
    var results = [];
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) results = results.concat(walk(file))
        else
        	if( file.split('.').pop() == "js") 
        	results.push(file);
    })
    return results;
}

if(argv.c)
{
	load_vars();
}

var files = walk(dir);	
var tmp_data = [];
var input = {};
console.log("$ SYSTEM: Files: " + files.length);
for( var cnt = 0; cnt < files.length; cnt++){
		console.log("$ SYSTEM: Reading File["+ cnt +"]: " + files[cnt]);
		var data = fs.readFileSync(files[cnt], "utf8");
		var start = new Date().getTime();
		var iss = scan(data);
		var end = new Date().getTime();
		input = {"id":i,"nome":files[cnt],"time":end-start,"issues":iss};
		adata.push(input);
}

//console.log(adata);
var d = new Date();
var path = __dirname + '/output' + d.getDate() + '-' + d.getMonth();

if(argv.o){
	//printout JSON format
	path = path.concat(".json");
	buffer = new Buffer(JSON.stringify(adata));
	fs.open(path, 'w', function(err, fd) {
    if (err) {
        throw 'error opening file: ' + err;
    } else {
        fs.write(fd, buffer, 0, buffer.length, null, function(err) {
            if (err) throw 'error writing file: ' + err;
            fs.close(fd, function() {
                console.log('$ SYSTEM: file written [' + path + ']');
            })
        });
    }
	});
}
else{
	p_html(adata);
}

//Save HTML format
function p_html(jsonobj){
	path = path.concat(".html");
	for(var xnt = 0; xnt < jsonobj.length; xnt++){
		var tmp_a = jsonobj[xnt].issues;
		htmlcontent = htmlcontent.concat("<br><table></br><tr><td><strong>["+jsonobj[xnt].id+"]</strong></td><td><strong>"+jsonobj[xnt].nome+"<strong></td><td>TimeScan:["+jsonobj[xnt].time+"]</br>");	
		for(var dnt = 0; dnt < tmp_a.length ; dnt++){
			htmlcontent = htmlcontent.concat("<tr><td><span style=\"color:"+ jsonobj[xnt].issues[dnt].css + "\">"+ jsonobj[xnt].issues[dnt].nome + "</span></td><td>"+ jsonobj[xnt].issues[dnt].line +"</td><td>"+ jsonobj[xnt].issues[dnt].code +"</td></tr>");
		}
	}
	buffer = new Buffer(htmlcontent);
	fs.open(path, 'w', function(err, fd) {
    if (err) {
        throw 'error opening file: ' + err;
    } else {
        fs.write(fd, buffer, 0, buffer.length, null, function(err) {
            if (err) throw 'error writing file: ' + err;
            fs.close(fd, function() {
                console.log('$ SYSTEM: file written [' + path + ']');
            })
        });
    }
	});

}

//Execute JSPrime function
function scan(data){
	//console.log(time);
	var ret = analyze(data); 
	var file_a = data.split('\n');
	
	var tmp_array = [];

	for(var i = 0; i < ret.length; i++){
		var color = ret[i][1];
		var tmp_i = "";
		var css = "";
		if ( color == 'orange'){
			tmp_i = "Active Source";
			css ="#ffc04c";
	    }
	    if ( color == 'yellow'){
			tmp_i = "Active Variable";
			css = "#ffff4c";
	    }
	    if ( color == 'grey'){
	    	tmp_i = "Non Active Variable";	
	    	css = "grey";
	    }
	    if ( color == 'BurlyWood'){
	    	tmp_i = "Non Active Source";
	    	css = "BurlyWood";
	    }
	    if ( color == '#FF00FF'){
	    	tmp_i = "Active function";
	    	css = "#ff7fff";
	    }
	    if ( color == 'red'){
			tmp_i = "Active Sink";
			css = "#ff6666";
	    }   
		tmp_array.push(new_issue(tmp_i,ret[i][0],file_a[ret[i][0]-1],css));
	}
	return tmp_array;
}

//create a new data struture
function new_issue(name,line,code,css){
	return {"nome": name, "line":line, "code": code, "css":css};
}
