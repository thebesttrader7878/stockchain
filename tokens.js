// Verified xStocks mints from Jupiter token API (isVerified, issuer Backed / xstocks.com)
export const USDC = { symbol:'USDC', name:'USD Coin', mint:'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', decimals:6, program:'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' };
const T22='TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const STOCKS = [
 ['AAPLx','Apple','XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp'],
 ['TSLAx','Tesla','XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB'],
 ['NVDAx','NVIDIA','Xsc9qvGR1efVDFGLrVsmkzv3qi45LTBjeUKSPmx9qEh'],
 ['SPYx','S&P 500','XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W'],
 ['QQQx','Nasdaq 100','Xs8S1uUs1zvS2p7iwtsG3b6fkhpvmwz4GYU3gWAmWHZ'],
 ['MSFTx','Microsoft','XspzcW1PRtgf6Wj92HCiZdjzKCyFekVD8P5Ueh3dRMX'],
 ['GOOGLx','Alphabet','XsCPL9dNWBMvFtTmwcCA5v3xWPSMEBCszbQdiLLq6aN'],
 ['AMZNx','Amazon','Xs3eBt7uRfJX8QUs4suhyU8p2M6DoUDrJyWBa8LLZsg'],
 ['METAx','Meta','Xsa62P5mvPszXL1krVUnU5ar38bBSVcWAB6fmPCo5Zu'],
 ['COINx','Coinbase','Xs7ZdzSHLU9ftNJsii5fCeJhoRWSC32SQGzGQtePxNu'],
].map(([symbol,name,mint])=>({symbol,name,mint,decimals:8,program:T22,logo:`https://xstocks-metadata.backed.fi/logos/tokens/${symbol}.png`}));
export const BY_MINT = Object.fromEntries([USDC,...STOCKS].map(t=>[t.mint,t]));
