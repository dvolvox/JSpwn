//SCANJS + JSPRIME TESTE CLI
// file is included here:
var fs = require('fs');

eval(fs.readFileSync(__dirname + '/common/analyzer.js') + '');
eval(fs.readFileSync(__dirname + '/common/engine.js') + '');

var argv = require('optimist').usage('Usage: $node jspwn.js -t [path/to/app] -j [for json output]').demand(['t']).argv;

var results = {};
var dir= argv.t;
var adata=[];
var res = "";
var htmlcontent = "<html><head><title>Output scanner</title></head><body>Data:"+ Date() + "</br><table>";
var time_scan = 0;
var cnt = 0;
var output = "";

//Recursive Function to sumarize all sub folder and files.
function walk(dir) {
    var results = [];
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) results = results.concat(walk(file))
        else results.push(file);
    })
    return results;
}

var files = walk(dir);
console.log("$ SYSTEM: Files: " + files);
for( var cnt = 0; cnt < files.length; cnt++){
	console.log(cnt);
	var data = fs.readFileSync(files[cnt], "utf8");
	var start = new Date().getTime();
	var iss = scan(data);
	var end = new Date().getTime();
	adata.push({"id":i,"nome":files[cnt],"time":end-start,"issues":iss});
}

//console.log(adata);
var d = new Date();
var path = __dirname + '/output' + d.getDate() + '-' + d.getMonth();


if(argv.o){
	//printout JSON format
	path = path.concat(".json");
	buffer = new Buffer(JSON.stringify(adata));
	console.log("Data to be written:" + adata);
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
			console.log(JSON.stringify(jsonobj[xnt].issues[1]));

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
