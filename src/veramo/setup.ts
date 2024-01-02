
// Core interfaces
import { createAgent, IDIDManager, IResolver, IDataStore, IKeyManager, ICredentialPlugin, ICredentialStatusVerifier } from '@veramo/core'

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'

// Ethr did identity provider
// Web did identity provider
import { WebDIDProvider } from '@veramo/did-provider-web'

// Core key manager plugin
import { KeyManager } from '@veramo/key-manager'

// Custom key management system for RN
//import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { SecretBox } from '@veramo/kms-local'


// W3C Verifiable Credential plugin
import { CredentialPlugin } from '@veramo/credential-w3c'

// Custom resolvers
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { getResolver as getDidPeerResolver, PeerDIDProvider } from '@veramo/did-provider-peer'

// Storage plugin using TypeOrm
import { Entities, KeyStore, DIDStore, IDataStoreORM, PrivateKeyStore, migrations, DataStoreORM } from '@veramo/data-store'


import { MessageHandler } from '@veramo/message-handler'
import { DIDComm, DIDCommMessageHandler } from '@veramo/did-comm'
import { JwtMessageHandler } from '@veramo/did-jwt'
import { CredentialIssuer, W3cMessageHandler } from '@veramo/credential-w3c'
import { ContextDoc, CredentialIssuerLD, LdDefaultContexts, VeramoEd25519Signature2018, VeramoEcdsaSecp256k1RecoverySignature2020 } from '@veramo/credential-ld'


// TypeORM is installed with `@veramo/data-store`
import { DataSource } from 'typeorm'
import { ISelectiveDisclosure, SelectiveDisclosure } from '@veramo/selective-disclosure'
import { JsonRpcProvider } from '@ethersproject/providers';
import { EthrDIDProvider } from '@veramo/did-provider-ethr'
import { KeyManagementSystem,  } from '@veramo/kms-local'
import { DataStore } from "@veramo/data-store";

// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = 'database.sqlite'

// You will need to get a project ID from infura https://www.infura.io
const ALCHEMY_PROJECT_ID = 'YJWEVVIfVUEXJQfSe3r0FEhGLUZbmkhK'
// This will be the secret key for the KMS
const KMS_SECRET_KEY =
  '11b574d316903ced6cc3f4787bbcc3047d9c72d1da4d83e36fe714ef785d10c1'

const dbConnection = new DataSource({
  type: 'sqlite',
  database: DATABASE_FILE,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['error', 'info', 'warn'],
  entities: Entities,
  
}).initialize()

export const MY_CUSTOM_CONTEXT_URI = "https://example.com/custom/context"
export const CITIZEN_CONTEXT_URI = "https://example.com/citizen/context"
export const MIA_IDENTITY_CONTEXT_URI = "https://localhost/MIA_identity/context"
export const MIA_IDENTITY_DOCUMENT_CONTEXT_URI = "https://localhost/MIA_identity_document/context"

const extraContexts: Record<string, ContextDoc> = {}
extraContexts[MY_CUSTOM_CONTEXT_URI] = {
  "@context": {
    "nothing": "https://example.com/custom/context",
  }
}

extraContexts[CITIZEN_CONTEXT_URI] = {
  "@context": {
    "familyName": "schema:familyName",
    "givenName": "schema:givenName",
    "number": "schema:number",
  }

}
//TODO: VERO: para la version del producto hay que cambiar regionalizar los textos de los fields usar un estandar y traducirlos
extraContexts[MIA_IDENTITY_CONTEXT_URI] = {
  "@context": {
    "Apellido": "schema:apellido",
    "Nombre": "schema:nombre",
    "TipoDocumento": "schema:tipo_documento",
    "Documento": "schema:number",
    "Sexo":"schema:sexo",
    "FechaNacimiento":"schema:fecha_nacimiento"
  }

}

extraContexts[MIA_IDENTITY_DOCUMENT_CONTEXT_URI] = {
  "@context": {
    "ParentHash": "schema:string",
    "Documento": "schema:number",
  }

}

// const checkStatus = (async (credential: any, didDoc: any) => {
//   //if (credential.credentialStatus.id == 1)
//   if(miaCredentialRevokedStore.get(credential.credentialStatus.id))
//     return revoked_true
//   else
//     return revoked_false
// }) 

export const agent = createAgent<IDIDManager & IKeyManager & IDataStore & IDataStoreORM & IResolver 
& ICredentialPlugin & ICredentialStatusVerifier & ISelectiveDisclosure >({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
        kms: {
            local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))), //local para bbs con
        },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      //defaultProvider: 'did:ethr:goerli',
      defaultProvider: 'did:ethr:polygon:testnet',
      //defaultProvider: 'did:ethr:0x13881',
      
      providers: {
        'did:ethr': new EthrDIDProvider({
          defaultKms: 'local',
          ttl: 60 * 60 * 24 * 30 * 12 + 1,
          networks: [
            /*{
              name: 'mainnet',
              rpcUrl: 'https://mainnet.infura.io/v3/' + INFURA_PROJECT_ID,
            },
            {
              name: 'goerli',
              rpcUrl: 'https://goerli.infura.io/v3/' + INFURA_PROJECT_ID,
            },
            {
              name: 'sepolia',
              chainId: 11155111,
              rpcUrl: 'https://sepolia.infura.io/v3/' + INFURA_PROJECT_ID,
            },
            {
              chainId: 421613,
              name: 'arbitrum:goerli',
              rpcUrl: 'https://arbitrum-goerli.infura.io/v3/' + INFURA_PROJECT_ID,
              registry: '0x8FFfcD6a85D29E9C33517aaf60b16FE4548f517E',
            },*/
            {
                name: 'polygon:testnet',
                chainId: 80001,
                rpcUrl: 'polygon-mumbai.g.alchemy.com/v2/JTT2FanfXJPoQl79pPKhq6VbhPHJiyKX',
                provider: new JsonRpcProvider('polygon-mumbai.g.alchemy.com/v2/JTT2FanfXJPoQl79pPKhq6VbhPHJiyKX', 80001)   
                
              }
          ],
        }),
        'did:web': new WebDIDProvider({
          defaultKms: 'local',
        }),
        'did:peer': new PeerDIDProvider({
          defaultKms: 'local',
        })
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...ethrDidResolver({
          name: 'polygon:testnet',
          chainId: 80001,
          rpcUrl: 'polygon-mumbai.g.alchemy.com/v2/JTT2FanfXJPoQl79pPKhq6VbhPHJiyKX'
          
        }),
        ...webDidResolver(),
        ...getDidPeerResolver()
      }),
    }),
    new CredentialPlugin(),
    new CredentialIssuer(),

    new CredentialIssuerLD({
      contextMaps: [LdDefaultContexts, extraContexts],
      suites: [
        new VeramoEd25519Signature2018(),
        new VeramoEcdsaSecp256k1RecoverySignature2020() //needed for did:ethr
      ]
    }),
    new SelectiveDisclosure(),
    new DIDComm(),
    new DataStore(dbConnection),
    new DataStoreORM(dbConnection),
    new MessageHandler({
      messageHandlers: [
        // in the case of message handlers, the order of handlers is important
        new DIDCommMessageHandler(),
        new JwtMessageHandler(),
        new W3cMessageHandler(),
      ],
    })
  ],
})

