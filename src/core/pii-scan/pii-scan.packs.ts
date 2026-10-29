import type { ValidatorName } from "./pii-scan.validators.ts";

/**
 * why: personal data is what a pseudonym preserves correlation for; special categories (health, belief, ethnicity)
 * are masked with no visible attribute, because even an email domain beside a diagnosis narrows who it is.
 */
export type PiiMode = "pseudonym" | "mask";

/**
 * A value shape the scanner finds anywhere in text, without a field name beside it.
 *
 * invariant: every detector here is either checksummed or distinctive by format alone. A document whose digits
 * prove nothing (a US SSN, a bare nine-digit NIF) is only ever a label in a pack, never a free-text detector.
 */
export type PiiDetector = { kind: string; pattern: string; validate?: ValidatorName };

export type PiiPack = {
  id: string;
  detectors?: readonly PiiDetector[];
  /** why: field names are how a name or an address is recognised — free text never says which word is a name. */
  labels?: Readonly<Record<string, string>>;
  mode?: PiiMode;
};

// why: the label lists use normalised names (lowercase, accents dropped, separators as `_`), the same form
// `normalizeLabel` turns a column or key into before looking it up.
const EN_LABELS: Record<string, string> = {
  name: "name",
  first_name: "name",
  last_name: "name",
  middle_name: "name",
  full_name: "name",
  given_name: "name",
  family_name: "name",
  surname: "name",
  maiden_name: "name",
  customer_name: "name",
  contact_name: "name",
  holder_name: "name",
  email: "email",
  e_mail: "email",
  email_address: "email",
  phone: "phone",
  phone_number: "phone",
  mobile: "phone",
  mobile_number: "phone",
  telephone: "phone",
  cell: "phone",
  cellphone: "phone",
  whatsapp: "phone",
  address: "address",
  street: "address",
  street_address: "address",
  address_line1: "address",
  address_line_1: "address",
  address_line2: "address",
  address_line_2: "address",
  postal_code: "address",
  postcode: "address",
  zip: "address",
  zip_code: "address",
  date_of_birth: "dob",
  dob: "dob",
  birth_date: "dob",
  birthdate: "dob",
  birthday: "dob",
  passport: "passport",
  passport_number: "passport",
  driver_license: "driver-license",
  drivers_license: "driver-license",
  license_number: "driver-license",
  ip_address: "ip",
  client_ip: "ip",
  remote_ip: "ip",
  // why: the address a person signed in or signed up from; a bare `ip` column is a pod's or a host's as often.
  login_ip: "ip",
  user_ip: "ip",
  signup_ip: "ip",
};

export const PACKS: readonly PiiPack[] = [
  {
    id: "global",
    detectors: [
      // why: the domain part must carry a dot and a letter TLD, so `user@host` in a git remote is left alone.
      {
        kind: "email",
        pattern: String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b`,
      },
      // why: E.164 with its leading `+` is international by construction; a national format needs a label.
      {
        kind: "phone",
        pattern: String.raw`(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,5}(?!\w)`,
        validate: "e164",
      },
      { kind: "card", pattern: String.raw`\b(?:\d[ -]?){12,18}\d\b`, validate: "card" },
      {
        kind: "iban",
        pattern: String.raw`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`,
        validate: "mod97",
      },
    ],
    labels: EN_LABELS,
  },
  {
    id: "id:br",
    detectors: [
      { kind: "br-cpf", pattern: String.raw`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`, validate: "br-cpf" },
      { kind: "br-cnpj", pattern: String.raw`\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b`, validate: "br-cnpj" },
    ],
    labels: { cpf: "br-cpf", cnpj: "br-cnpj", rg: "br-rg", cpf_cnpj: "br-cpf", documento: "national-id" },
  },
  {
    id: "id:us",
    labels: { ssn: "us-ssn", social_security_number: "us-ssn", ein: "us-ein", itin: "us-itin" },
  },
  { id: "id:uk", labels: { nino: "uk-nino", national_insurance_number: "uk-nino", ni_number: "uk-nino" } },
  {
    id: "id:es",
    detectors: [{ kind: "es-dni", pattern: String.raw`\b[XYZ]?\d{7,8}-?[A-Z]\b`, validate: "es-dni" }],
    labels: { dni: "es-dni", nie: "es-dni", nif: "es-dni" },
  },
  { id: "id:pt", labels: { nif: "pt-nif", numero_contribuinte: "pt-nif", cartao_cidadao: "pt-cc" } },
  {
    id: "id:fr",
    detectors: [
      {
        kind: "fr-nir",
        pattern: String.raw`\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b`,
        validate: "fr-nir",
      },
    ],
    labels: { nir: "fr-nir", numero_securite_sociale: "fr-nir", insee: "fr-nir" },
  },
  {
    id: "id:de",
    labels: {
      steuer_id: "de-steuer-id",
      steueridentifikationsnummer: "de-steuer-id",
      personalausweis: "de-id",
    },
  },
  { id: "id:it", labels: { codice_fiscale: "it-cf" } },
  { id: "id:mx", labels: { curp: "mx-curp", rfc: "mx-rfc" } },
  {
    id: "id:ar",
    detectors: [
      { kind: "ar-cuit", pattern: String.raw`\b(?:20|23|24|27|30|33|34)-\d{8}-\d\b`, validate: "ar-cuit" },
    ],
    labels: { cuit: "ar-cuit", cuil: "ar-cuit" },
  },
  {
    id: "id:in",
    detectors: [
      { kind: "in-aadhaar", pattern: String.raw`\b[2-9]\d{3} \d{4} \d{4}\b`, validate: "verhoeff" },
    ],
    labels: { aadhaar: "in-aadhaar", pan: "in-pan" },
  },
  {
    id: "id:ca",
    detectors: [{ kind: "ca-sin", pattern: String.raw`\b\d{3}[ -]\d{3}[ -]\d{3}\b`, validate: "luhn" }],
    labels: { sin: "ca-sin", social_insurance_number: "ca-sin" },
  },
  { id: "id:au", labels: { tfn: "au-tfn", tax_file_number: "au-tfn" } },
  { id: "lang:en", labels: EN_LABELS },
  {
    id: "lang:pt",
    labels: {
      nome: "name",
      nome_completo: "name",
      primeiro_nome: "name",
      sobrenome: "name",
      telefone: "phone",
      celular: "phone",
      endereco: "address",
      logradouro: "address",
      cep: "address",
      data_nascimento: "dob",
      data_de_nascimento: "dob",
      nascimento: "dob",
    },
  },
  {
    id: "lang:es",
    labels: {
      nombre: "name",
      nombre_completo: "name",
      apellido: "name",
      apellidos: "name",
      correo: "email",
      correo_electronico: "email",
      telefono: "phone",
      movil: "phone",
      direccion: "address",
      codigo_postal: "address",
      fecha_nacimiento: "dob",
      fecha_de_nacimiento: "dob",
    },
  },
  {
    id: "lang:fr",
    labels: {
      nom: "name",
      prenom: "name",
      nom_complet: "name",
      courriel: "email",
      telephone: "phone",
      portable: "phone",
      adresse: "address",
      code_postal: "address",
      date_naissance: "dob",
      date_de_naissance: "dob",
    },
  },
  {
    id: "lang:de",
    labels: {
      vorname: "name",
      nachname: "name",
      telefon: "phone",
      handy: "phone",
      adresse: "address",
      strasse: "address",
      plz: "address",
      geburtsdatum: "dob",
    },
  },
  {
    id: "lang:it",
    labels: {
      nome: "name",
      cognome: "name",
      telefono: "phone",
      cellulare: "phone",
      indirizzo: "address",
      cap: "address",
      data_nascita: "dob",
      data_di_nascita: "dob",
    },
  },
  {
    id: "domain:finance",
    labels: {
      account_number: "account",
      numero_conta: "account",
      conta: "account",
      agencia: "account",
      routing_number: "account",
      card_number: "card",
      cardholder_name: "name",
      tax_id: "national-id",
    },
  },
  {
    id: "domain:hr",
    labels: {
      salary: "salary",
      salario: "salary",
      wage: "salary",
      employee_id: "employee-id",
      matricula: "employee-id",
    },
  },
  {
    id: "domain:health",
    mode: "mask",
    labels: {
      diagnosis: "health",
      diagnostico: "health",
      icd: "health",
      icd10: "health",
      allergy: "health",
      allergies: "health",
      medication: "health",
      prescription: "health",
      patient_id: "health",
      medical_record_number: "health",
      mrn: "health",
      blood_type: "health",
      health_insurance_number: "health",
    },
  },
  {
    id: "domain:special",
    mode: "mask",
    labels: {
      religion: "special",
      religiao: "special",
      ethnicity: "special",
      etnia: "special",
      race: "special",
      raca: "special",
      sexual_orientation: "special",
      orientacao_sexual: "special",
      political_affiliation: "special",
      union_membership: "special",
      biometric: "special",
      fingerprint: "special",
      genetic_data: "special",
    },
  },
];

/**
 * why: with no project template the audience is unknown, so every pack whose free-text detectors are checksummed
 * is on — a checksum is what makes enabling a country nobody asked for cheap. Label-only packs wait for the project
 * to declare them, because a bare `nif` or `ssn` column means nothing without knowing the project serves that country.
 */
export const DEFAULT_PACKS: readonly string[] = [
  "global",
  "id:br",
  "id:es",
  "id:fr",
  "id:ar",
  "id:in",
  "id:ca",
  // why: a language pack only names fields, so enabling every one costs nothing a field name did not already say.
  "lang:pt",
  "lang:es",
  "lang:fr",
  "lang:de",
  "lang:it",
];

export function packById(id: string): PiiPack | undefined {
  return PACKS.find((pack) => pack.id === id);
}
