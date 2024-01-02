import { agent } from './../veramo/setup.js'

async function main() {
  
   let alias = 'default_1'
   
  const identifier = await agent.didManagerGetOrCreate({kms: 'local', alias: alias })
/*
  const newKey = await agent.keyManagerCreate({
    kms: 'local',
    type: 'Secp256k1',
  })*/

  const newKey = await agent.keyManagerGet({
    kid: '04ba719e618495a36b7a67f06c67fb758cfea767790323a489bbcf1329fd0978e82778c2159db190a68135d2c8356c9f0622efebd51cce8cb19281c57de92b4eb6'
  })


  const result = await agent.didManagerAddKey({
    did: identifier.did,
    key: newKey
  })

  

  
  console.log(`New identifier created`)
  console.log(JSON.stringify(identifier, null, 2))

  
  console.log(`result`)
  console.log(JSON.stringify(result, null, 2))
}

main().catch(console.log)