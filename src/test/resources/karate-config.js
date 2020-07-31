function() {
	
	var stream = read('classpath:karate.properties');
	var props = new java.util.Properties();
	props.load(stream);
	//karate.log('properties= ', props);
	 
    var env = props.get('karate.env'); // get java system property 'karate.env'
    var username = props.get('karate.user');
    var password = props.get('karate.pass');
    //karate.log('karate.env selected environment is:', env);
    //karate.log('karate user:pwd =', username+':'+password);
    karate.configure("ssl", true);
    
    if (!env) {
    env = 'dev'; //env can be anything: dev, qa, staging, etc.
    }
    
    var baseUrl = props.get('karate.test.url');
    var port = props.get('karate.test.port');
    //karate.log('karate baseUrl:port =', baseUrl+':'+port);
    var config = {
	    env: env,
	    
	    // default accessToken
	    
	    accessToken: 'c8dd2445-4734-4119-8dd1-4dbe91976202',
	    
	   //#1 - health endpoint
	    healthUrl: baseUrl + ':' + port + '/health',
	    
	   //#2 - backchannel
	    backchannelUrl: baseUrl + ':' + port + '/api/v1/oxauth/backchannel',
	    
	    //#1 - metrics endpoint
	    metricsUrl: baseUrl + ':' + port + '/api/v1/oxauth/metrics',

	    //#11 - sessionId endpoint
	    sessionidUrl: baseUrl + ':' + port + '/api/v1/oxauth/sessionid',
	    
	    // OpenIdConnect Clients Endpoint
	    openidclients_url: baseUrl + ':' + port + '/api/v1/oxauth/clients',
	    
	    };

    
    karate.configure('connectTimeout', 30000);
    karate.configure('readTimeout', 60000);
    
    return config;
}