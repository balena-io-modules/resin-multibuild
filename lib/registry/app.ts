/* eslint-disable @typescript-eslint/no-var-requires */
//import { Registry } from "./registry";

import * as rc from "./registry-client";


// function sleep(ms: number) {
//     return new Promise(resolve => setTimeout(resolve, ms));
//   }
  
const runpoc = async () => {
    // var r = new Registry();
    // const resp = await r.getImageManifest(
    //     { 
    //         name: 'nginx'
    //     }
    // );
    // console.log(resp);

    //const drc = require('./registry-client-v2');
    //const REPO = 'pjbalenista/multiarch-test2';
    const REPO = 'gcr.io/google_containers/pause';

    const client = new rc.RegistryClient(
        {
            name: REPO, 
//            username: "pjbalenista", 
//            password: "51d96c77-d8e2-4a51-8fe8-c01a84537a21",
        });
    //const loginInfo = await client.login();
    //console.log(loginInfo);

    // const client = rc.createClient({name: REPO, username: "pjbalenista", password: "51d96c77-d8e2-4a51-8fe8-c01a84537a21"});

    const manifest = await client.getManifest("latest", 2);
    console.log(manifest);
    console.log("done");
}

runpoc().then(() => {
    console.log("done");
});
